"""Криптографические операции сервера.

Совместимо с psi_agent.crypto:
    - Ed25519       — подпись RenderedConfig
    - X25519        — шифрование секретов для агента
    - HKDF-SHA256 + ChaCha20Poly1305 — фактическая схема шифрования
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.core.exceptions import ValidationError

from .models import Agent, BulkDeployment, Deployment, ServerIdentity
from .perms import ACTIVE_STATUSES

HKDF_INFO = b"psi-agent-secret-v1"


# --- Генерация ключей ---

def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


# --- Шифрование секрета для агента ---

def encrypt_for_agent(agent_pubkey_x25519_pem: str, plaintext: str) -> dict:
    """Шифрует секрет публичным X25519 ключом агента.

    Схема идентична psi_agent.crypto.encrypt_x25519.
    """
    recipient_pub = serialization.load_pem_public_key(
        agent_pubkey_x25519_pem.encode()
    )
    ephemeral_priv = X25519PrivateKey.generate()
    shared = ephemeral_priv.exchange(recipient_pub)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO,
    ).derive(shared)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode(), None)
    return {
        "encoding": "x25519-chacha20poly1305",
        "ephemeral_pub": base64.b64encode(
            ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


# --- Подпись RenderedConfig ---

def canonical_payload(config_dict: dict) -> bytes:
    """Канонический вид: sort_keys, ensure_ascii=False, без поля signature."""
    payload = {k: v for k, v in config_dict.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign_rendered_config(config_dict: dict, privkey_ed25519_pem: str) -> dict:
    """Возвращает config с добавленным полем signature."""
    payload = canonical_payload(config_dict)
    priv = serialization.load_pem_private_key(
        privkey_ed25519_pem.encode(), password=None,
    )
    sig = priv.sign(payload)
    return {
        **{k: v for k, v in config_dict.items() if k != "signature"},
        "signature": {
            "algo": "ed25519",
            "value": base64.b64encode(sig).decode(),
        },
    }


# --- Утилиты ---

def iso_utc(dt: datetime) -> str:
    """ISO 8601 в UTC, совместимо с pydantic model_dump(mode='json')."""
    return dt.astimezone(UTC).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def active_deployment_for(host) -> Deployment | None:
    return (
        Deployment.objects
        .filter(host=host, status__in=ACTIVE_STATUSES)
        .order_by("-created_at")
        .first()
    )


def create_deployment(host, *, user=None, priority: int = 0) -> Deployment:
    active = active_deployment_for(host)
    if active is not None:
        raise ValidationError(
            f"У хоста {host.hostname} уже есть активная задача "
            f"({active.get_status_display()}, {active.id}). "
            "Дождитесь её завершения или отмените."
        )
    return Deployment.objects.create(
        host=host, priority=priority, created_by=user,
        status=Deployment.Status.PENDING,
    )

def compute_config_hash(host) -> str:
    """Стабильный sha256 от финального settings + hardening хоста."""
    payload = {
        "settings": host.resolved_settings(),
        "hardening": host.resolved_hardening(),
    }
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def update_host_state(host) -> dict:
    """Считает текущий hash, обновляет drift_checked_at/drift_detected_at.

    Возвращает {"state": "clean"|"drift"|"unsynced", "hash": str}.
    """
    current = compute_config_hash(host)
    if not host.last_deployed_config_hash:
        state = "unsynced"
    elif current == host.last_deployed_config_hash:
        state = "clean"
    else:
        state = "drift"

    now = timezone.now()
    host.drift_checked_at = now
    host.drift_detected_at = (
        (host.drift_detected_at or now) if state == "drift" else None
    )
    host.save(update_fields=["drift_checked_at", "drift_detected_at"])
    return {"state": state, "hash": current}


def update_host_hash_after_deployment(deployment: Deployment) -> None:
    """После успешного (или частичного) применения — зафиксировать hash."""
    if deployment.status not in (
        Deployment.Status.SUCCESS, Deployment.Status.PARTIAL,
    ):
        return
    host = deployment.host
    host.last_deployed_config_hash = compute_config_hash(host)
    host.last_deployed_at = timezone.now()
    host.drift_detected_at = None
    host.save(update_fields=[
        "last_deployed_config_hash", "last_deployed_at", "drift_detected_at",
    ])


def bulk_create_deployments(
    host_ids: list[int], *, user=None, name: str = "",
) -> dict:
    """Создать BulkDeployment + Deployment на каждый хост.

    Возвращает {"bulk", "created", "skipped", "errors"}.
    Пропускаются хосты, у которых уже есть активная задача.
    """
    from apps.inventory.models import Host

    hosts = (
        Host.objects
        .filter(pk__in=host_ids)
        .select_related("domain", "host_set")
    )

    bulk = BulkDeployment.objects.create(
        name=name or f"Bulk {timezone.now():%Y-%m-%d %H:%M}",
        created_by=user,
        status=BulkDeployment.Status.PENDING,
    )

    created: list[Deployment] = []
    skipped: list[dict] = []
    errors: list[dict] = []

    for host in hosts:
        try:
            dep = create_deployment(host, user=user)
            dep.bulk_deployment = bulk
            dep.save(update_fields=["bulk_deployment"])
            created.append(dep)
        except ValidationError as exc:
            skipped.append({"host": host, "reason": str(exc.message)})
        except Exception as exc:
            errors.append({"host": host, "reason": str(exc)})

    bulk.total = len(created)
    bulk.status = (
        BulkDeployment.Status.RUNNING if created
        else BulkDeployment.Status.FAILED
    )
    bulk.save(update_fields=["total", "status"])

    return {"bulk": bulk, "created": created, "skipped": skipped, "errors": errors}


def cancel_bulk(bulk: BulkDeployment) -> int:
    """Отменяет все активные задачи в батче. Возвращает количество отменённых."""
    now = timezone.now()
    active = bulk.deployments.filter(status__in=[
        Deployment.Status.PENDING,
        Deployment.Status.DISPATCHED,
        Deployment.Status.RUNNING,
    ])
    count = active.update(status=Deployment.Status.CANCELLED, finished_at=now)
    bulk.status = BulkDeployment.Status.CANCELLED
    bulk.save(update_fields=["status"])
    bulk.recompute()
    return count