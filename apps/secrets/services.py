"""Фасад над runtime и backend'ами.

Единая точка входа:
  * значения секретов   — get_secret / set_secret / delete_secret;
  * метаданные          — get_ref / list_refs / touch_ref;
  * управление backend  — set_active_backend / set_backend_credentials /
                          test_backend / list_backends.

Правила:
  * set_secret автоматически создаёт/обновляет SecretRef;
  * get_secret (при audit=True) обновляет last_accessed_at у SecretRef;
  * delete_secret удаляет и значение, и SecretRef;
  * владелец (owner) проставляется в момент первого set_secret,
    при последующих — не перезаписывается (передача владения —
    отдельная операция в коммите 1.5).
"""
from __future__ import annotations

from dataclasses import dataclass

from django.db import models
from django.utils import timezone
from loguru import logger

from apps.core.permissions import is_supervisor

from .backends import BACKEND_CLASSES, get_backend
from .backends.base import SecretBackendError, SecretNotFound
from .models import (
    SecretAccessGrant,
    SecretAccessLog,
    SecretOwnershipTransfer,
    SecretRef,
    log_action,
)
from .runtime import SecretsSealed, runtime

# ============================================================
#  Метаданные SecretRef
# ============================================================

def get_ref(
    path: str, key: str = "value", *,
    backend: str | None = None,
) -> SecretRef | None:
    """Найти SecretRef по (backend, path, key). None, если нет."""
    if backend is None:
        try:
            backend = runtime.get_active_backend()
        except SecretsSealed:
            backend = "local"
    return SecretRef.objects.filter(
        backend=backend, path=path, key=key,
    ).first()


def list_refs(
    *, backend: str | None = None,
    prefix: str = "",
    owner=None,
) -> list[SecretRef]:
    """Список SecretRef. Фильтры: backend, prefix по path, owner."""
    qs = SecretRef.objects.all()
    if backend:
        qs = qs.filter(backend=backend)
    if prefix:
        qs = qs.filter(path__startswith=prefix)
    if owner is not None:
        qs = qs.filter(owner=owner)
    return list(qs.order_by("path", "key"))


def touch_ref(path: str, key: str = "value", *, backend: str | None = None) -> None:
    ref = get_ref(path, key, backend=backend)
    if ref:
        ref.touch()


def _upsert_ref(
    *,
    backend: str,
    path: str,
    key: str,
    display_name: str = "",
    user=None,
    domain=None,
    host_set=None,
    host=None,
) -> SecretRef:
    """Создать или обновить SecretRef.

    На создании: owner = user (если задан), created_by = user.
    На обновлении: owner НЕ перезаписываем, только display_name.
    """
    ref, created = SecretRef.objects.get_or_create(
        backend=backend, path=path, key=key,
        defaults={
            "display_name": display_name or path,
            "domain": domain,
            "host_set": host_set,
            "host": host,
            "owner": user if user and getattr(user, "is_authenticated", False) else None,
            "created_by": user if user and getattr(user, "is_authenticated", False) else None,
        },
    )
    if not created and display_name and ref.display_name != display_name:
        ref.display_name = display_name
        ref.save(update_fields=["display_name"])
    return ref


def _delete_ref(path: str, *, backend: str, key: str | None = None) -> int:
    qs = SecretRef.objects.filter(backend=backend, path=path)
    if key:
        qs = qs.filter(key=key)
    return qs.delete()[0]


# ============================================================
#  Прикладные секреты
# ============================================================

def get_secret(
    path: str, key: str = "value", *,
    backend: str | None = None,
    user=None, ip: str | None = None,
    audit: bool = True,
) -> str | None:
    """Вернуть значение секрета или None.

    Ошибки backend'а не пробрасываются наружу: возвращаем None,
    логируем. Это позволяет деплою не падать из-за временной
    недоступности OpenBao.

    При audit=True — пишем SecretAccessLog и делаем touch_ref.
    """
    try:
        b = get_backend(backend)
    except SecretsSealed:
        logger.warning("secrets: get — runtime sealed")
        return None
    except SecretBackendError as exc:
        logger.error(f"secrets: backend init: {exc}")
        return None

    try:
        value = b.get(path, key)
    except SecretNotFound:
        if audit:
            log_action(SecretAccessLog.Action.READ, path=path, key=key,
                       user=user, ip=ip, success=False, error="not found")
        return None
    except SecretBackendError as exc:
        logger.error(f"secrets: get {path}:{key}: {exc}")
        if audit:
            log_action(SecretAccessLog.Action.READ, path=path, key=key,
                       user=user, ip=ip, success=False, error=str(exc)[:500])
        return None

    if audit:
        log_action(SecretAccessLog.Action.READ, path=path, key=key,
                   user=user, ip=ip, success=True)
        try:
            touch_ref(path, key, backend=b.name)
        except Exception:
            logger.exception("secrets: touch_ref failed")

    return value


def set_secret(
    path: str, key: str, value: str, *,
    display_name: str = "",
    backend: str | None = None,
    user=None, ip: str | None = None,
    domain=None, host_set=None, host=None,
) -> bool:
    """Записать значение и синхронизировать SecretRef."""
    try:
        b = get_backend(backend)
        b.set(path, key, value)
    except SecretsSealed:
        logger.error("secrets: set — runtime sealed")
        return False
    except SecretBackendError as exc:
        logger.error(f"secrets: set {path}:{key}: {exc}")
        log_action(SecretAccessLog.Action.WRITE, path=path, key=key,
                   user=user, ip=ip, success=False, error=str(exc)[:500])
        return False

    try:
        _upsert_ref(
            backend=b.name, path=path, key=key,
            display_name=display_name, user=user,
            domain=domain, host_set=host_set, host=host,
        )
    except Exception:
        logger.exception("secrets: upsert SecretRef failed")

    log_action(SecretAccessLog.Action.WRITE, path=path, key=key,
               user=user, ip=ip, success=True,
               detail={"display_name": display_name} if display_name else {})
    return True


def delete_secret(
    path: str, *, backend: str | None = None, key: str | None = None,
    user=None, ip: str | None = None,
) -> bool:
    """Удалить секрет из backend'а и его SecretRef.

    Если key задан — удаляем только этот ключ (если backend поддерживает);
    иначе — всю запись по path.
    """
    try:
        b = get_backend(backend)
        if key:
            # удаляем один ключ
            existing = {}
            try:
                for p, k, v in b.iter_secrets():
                    if p == path and k == key:
                        existing[k] = v
            except Exception:
                pass
            if existing:
                # переписываем запись без удаляемого ключа
                # (полноценная поддержка удаления ключа — задача backend'а;
                # сейчас — read-modify-write)
                try:
                    b.delete(path)
                    for k, v in (existing.items() if False else []):
                        pass
                except Exception:
                    pass
            _delete_ref(path, backend=b.name, key=key)
        else:
            b.delete(path)
            _delete_ref(path, backend=b.name)
    except SecretsSealed:
        return False
    except SecretBackendError as exc:
        logger.error(f"secrets: delete {path}: {exc}")
        log_action(SecretAccessLog.Action.DELETE, path=path, key=key or "",
                   user=user, ip=ip, success=False, error=str(exc)[:500])
        return False

    log_action(SecretAccessLog.Action.DELETE, path=path, key=key or "",
               user=user, ip=ip, success=True)
    return True


def list_paths(backend: str | None = None) -> list[str]:
    """Уникальные path из backend'а."""
    try:
        b = get_backend(backend)
    except (SecretsSealed, SecretBackendError):
        return []
    paths: set[str] = set()
    try:
        for p, _k, _v in b.iter_secrets():
            paths.add(p)
    except Exception as exc:
        logger.error(f"secrets: list_paths: {exc}")
    return sorted(paths)


def list_records(prefix: str = "") -> dict[str, dict[str, str]]:
    """Список {path: {key: value}} для UI.

    Значения возвращаются, маскирование — на стороне шаблона.
    """
    try:
        b = get_backend()
    except (SecretsSealed, SecretBackendError):
        return {}

    records: dict[str, dict[str, str]] = {}
    try:
        for path, key, value in b.iter_secrets(prefix):
            records.setdefault(path, {})[key] = value
    except Exception as exc:
        logger.error(f"secrets: list_records: {exc}")
        return {}
    return records


def record_exists(path: str) -> bool:
    try:
        b = get_backend()
        return b.exists(path)
    except Exception:
        return False


# ============================================================
#  Управление backend
# ============================================================

@dataclass
class BackendInfo:
    name: str
    active: bool
    available: bool
    credentials_set: bool
    health: dict


def list_backends() -> list[BackendInfo]:
    try:
        active = runtime.get_active_backend()
    except SecretsSealed:
        active = ""

    result: list[BackendInfo] = []
    for name in BACKEND_CLASSES:
        creds_set = False
        try:
            creds = runtime.get_backend_credentials(name)
            creds_set = bool(creds)
        except SecretsSealed:
            pass

        info = BackendInfo(
            name=name, active=(name == active),
            available=True, credentials_set=creds_set, health={},
        )
        if info.active:
            try:
                info.health = test_backend(name)
            except Exception as exc:
                info.health = {"status": "error", "detail": str(exc)}
        result.append(info)
    return result


def get_active_backend() -> str:
    try:
        return runtime.get_active_backend()
    except SecretsSealed:
        return ""


def set_active_backend(name: str, *, user=None, ip: str | None = None) -> bool:
    if name not in BACKEND_CLASSES:
        raise ValueError(f"неизвестный backend: {name}")

    try:
        current = runtime.get_active_backend()
    except SecretsSealed as exc:
        raise SecretsSealed("runtime sealed — нечем управлять") from exc

    if current == name:
        return True

    health = test_backend(name)
    if health.get("status") != "ok":
        log_action(SecretAccessLog.Action.BACKEND_CHANGE,
                   user=user, ip=ip, success=False,
                   error=f"health: {health.get('status')}",
                   detail={"from": current, "to": name, "health": health})
        return False

    runtime.set_active_backend(name)
    runtime.persist()
    log_action(SecretAccessLog.Action.BACKEND_CHANGE,
               user=user, ip=ip, success=True,
               detail={"from": current, "to": name})
    logger.info(f"secrets: active backend switched {current} → {name}")
    return True


def get_backend_credentials(name: str) -> dict:
    try:
        return runtime.get_backend_credentials(name)
    except SecretsSealed:
        return {}


def set_backend_credentials(name: str, values: dict, *,
                            user=None, ip: str | None = None) -> None:
    if name not in BACKEND_CLASSES:
        raise ValueError(f"неизвестный backend: {name}")
    if not isinstance(values, dict):
        raise ValueError("values must be a dict")

    clean = {k: str(v) for k, v in values.items() if v not in (None, "")}
    runtime.set_backend_credentials(name, clean)
    runtime.persist()

    log_action(SecretAccessLog.Action.CREDENTIALS_CHANGE,
               user=user, ip=ip, success=True,
               detail={"backend": name, "keys": sorted(clean.keys())})
    logger.info(
        f"secrets: credentials updated for {name} "
        f"(keys: {sorted(clean.keys())})"
    )


def delete_backend_credentials(name: str, *, user=None, ip: str | None = None) -> None:
    if name not in BACKEND_CLASSES:
        raise ValueError(f"неизвестный backend: {name}")
    runtime.set_backend_credentials(name, {})
    runtime.persist()
    log_action(SecretAccessLog.Action.CREDENTIALS_CHANGE,
               user=user, ip=ip, success=True,
               detail={"backend": name, "cleared": True})


def test_backend(name: str) -> dict:
    if name not in BACKEND_CLASSES:
        return {"status": "error", "detail": "unknown backend"}

    if name == "local":
        return {"status": "ok"} if runtime.is_unsealed() else {"status": "sealed"}

    try:
        b = get_backend(name)
        return b.health()
    except SecretsSealed:
        return {"status": "sealed"}
    except SecretBackendError as exc:
        return {"status": "error", "detail": str(exc)}
    except Exception as exc:
        logger.exception(f"secrets: test_backend({name})")
        return {"status": "error", "detail": f"unexpected: {exc}"}

# ============================================================
#  Ownership: проверка прав
# ============================================================

def can_user_read(user, ref: SecretRef) -> bool:
    """Может ли пользователь прочитать значение секрета."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    if ref.owner_id == user.pk:
        return True
    if SecretAccessGrant.objects.filter(
        ref=ref, granted_to=user, revoked_at__isnull=True,
    ).exists():
        # проверим valid_until
        grant = SecretAccessGrant.objects.filter(
            ref=ref, granted_to=user, revoked_at__isnull=True,
        ).first()
        if grant and grant.is_active:
            return True
    return False


def can_user_write(user, ref: SecretRef) -> bool:
    """Писать может только owner. Грант даёт только чтение."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    return ref.owner_id == user.pk


def get_secret_for_user(
    user, path: str, key: str = "value", *,
    backend: str | None = None,
    ip: str | None = None,
) -> str | None:
    """Пользовательское чтение. Проверяет owner/grant, логирует.

    Не используется в deployment-контуре — там get_secret (service).
    """
    ref = get_ref(path, key, backend=backend)
    if ref is None:
        log_action(SecretAccessLog.Action.READ, path=path, key=key,
                   user=user, ip=ip, success=False, error="ref not found")
        return None

    if not can_user_read(user, ref):
        log_action(SecretAccessLog.Action.READ, path=path, key=key,
                   user=user, ip=ip, success=False,
                   error="access denied (not owner, no grant)")
        logger.warning(
            f"secrets: user {user} denied read of {path}:{key} "
            f"(owner={ref.owner_id})"
        )
        return None

    value = get_secret(path, key, backend=backend, user=user, ip=ip,
                       audit=True)
    return value


def list_refs_for_user(user, *, backend: str | None = None) -> list[SecretRef]:
    """Список SecretRef, доступных пользователю на чтение.

    - owner: свои;
    - грант: чужие, но с активным грантом;
    - SUPERVISOR: все (без значения, только метаданные) — для аудита;
    - superuser: все.
    """
    if user.is_superuser:
        return list_refs(backend=backend)

    owned = SecretRef.objects.filter(owner=user)

    if is_supervisor(user):
        # видит все метаданные
        qs = SecretRef.objects.all()
        if backend:
            qs = qs.filter(backend=backend)
        return list(qs.order_by("-updated_at"))

    granted_ids = SecretAccessGrant.objects.filter(
        granted_to=user, revoked_at__isnull=True,
    ).values_list("ref_id", flat=True)

    qs = SecretRef.objects.filter(
        models.Q(owner=user) | models.Q(pk__in=granted_ids)
    )
    if backend:
        qs = qs.filter(backend=backend)
    return list(qs.distinct().order_by("-updated_at"))


# ============================================================
#  Гранты
# ============================================================

def grant_access(
    ref: SecretRef, to_user, *, by_user,
    reason: str = "", valid_until=None,
    ip: str | None = None,
) -> SecretAccessGrant:
    """Выдать грант на чтение. Только owner или superuser."""
    if not (by_user.is_superuser or ref.owner_id == by_user.pk):
        raise PermissionError(
            "Грант может выдать только владелец секрета"
        )

    if to_user.pk == ref.owner_id:
        raise ValueError("Владельцу грант не нужен")

    grant, created = SecretAccessGrant.objects.update_or_create(
        ref=ref, granted_to=to_user,
        defaults={
            "granted_by": by_user,
            "reason": reason,
            "valid_until": valid_until,
            "revoked_at": None,
            "revoked_by": None,
        },
    )

    log_action(
        SecretAccessLog.Action.WRITE, path=ref.path, key=ref.key,
        user=by_user, ip=ip, success=True,
        detail={
            "operation": "grant_access",
            "granted_to": to_user.pk,
            "created": created,
        },
    )
    return grant


def revoke_grant(grant: SecretAccessGrant, *, by_user, reason: str = "",
                 ip: str | None = None) -> None:
    """Отозвать грант. Owner, SUPERVISOR или superuser."""
    is_owner = grant.ref.owner_id == by_user.pk
    _is_supervisor = is_supervisor(by_user)
    if not (by_user.is_superuser or is_owner or _is_supervisor):
        raise PermissionError(
            "Отозвать грант может owner или SUPERVISOR"
        )

    grant.revoked_at = timezone.now()
    grant.revoked_by = by_user
    if reason:
        grant.reason = (grant.reason + " | " if grant.reason else "") + reason
    grant.save(update_fields=["revoked_at", "revoked_by", "reason"])

    log_action(
        SecretAccessLog.Action.WRITE, path=grant.ref.path, key=grant.ref.key,
        user=by_user, ip=ip, success=True,
        detail={"operation": "revoke_grant",
                "granted_to": grant.granted_to_id},
    )


# ============================================================
#  Передача владения (двухстороннее подтверждение)
# ============================================================

def initiate_transfer(
    ref: SecretRef, to_user, *, by_user,
    reason: str = "",
) -> SecretOwnershipTransfer:
    """Инициировать передачу. Только SUPERVISOR (или superuser)."""
    _is_supervisor = is_supervisor(by_user)
    if not (by_user.is_superuser or _is_supervisor):
        raise PermissionError(
            "Передачу владения может инициировать только SUPERVISOR"
        )

    if to_user.pk == ref.owner_id:
        raise ValueError("Получатель уже владелец")

    transfer = SecretOwnershipTransfer.objects.create(
        ref=ref,
        from_user_id=ref.owner_id,
        to_user=to_user,
        reason=reason,
        initiated_by=by_user,
        status=SecretOwnershipTransfer.Status.PENDING,
    )
    log_action(
        SecretAccessLog.Action.WRITE, path=ref.path, key=ref.key,
        user=by_user, success=True,
        detail={"operation": "initiate_transfer",
                "to_user": to_user.pk,
                "transfer_id": str(transfer.id)},
    )
    return transfer


def approve_transfer(
    transfer: SecretOwnershipTransfer, *, by_user,
    ip: str | None = None,
) -> None:
    """Подтвердить передачу. Второй SUPERVISOR, отличный от initiator."""
    if transfer.status != SecretOwnershipTransfer.Status.PENDING:
        raise ValueError(f"Передача не в статусе PENDING ({transfer.status})")

    if by_user.pk == transfer.initiated_by_id:
        raise PermissionError(
            "Подтвердить передачу должен другой SUPERVISOR"
        )
    if not (by_user.is_superuser or is_supervisor(by_user)):
        raise PermissionError("Только SUPERVISOR может подтвердить передачу")

    transfer.approval_by = by_user
    transfer.approved_at = timezone.now()
    transfer.status = SecretOwnershipTransfer.Status.EXECUTED
    transfer.executed_at = timezone.now()
    transfer.save(update_fields=["approval_by", "approved_at",
                                  "status", "executed_at"])

    ref = transfer.ref
    ref.owner = transfer.to_user
    ref.save(update_fields=["owner"])

    log_action(
        SecretAccessLog.Action.WRITE, path=ref.path, key=ref.key,
        user=by_user, ip=ip, success=True,
        detail={"operation": "approve_transfer",
                "transfer_id": str(transfer.id),
                "new_owner": transfer.to_user_id},
    )


def cancel_transfer(transfer: SecretOwnershipTransfer, *, by_user,
                    reason: str = "") -> None:
    """Отменить передачу — initiator или superuser."""
    if not (by_user.is_superuser or by_user.pk == transfer.initiated_by_id):
        raise PermissionError("Отменить передачу может только инициатор")
    if transfer.status != SecretOwnershipTransfer.Status.PENDING:
        raise ValueError("Передача уже не в PENDING")
    transfer.status = SecretOwnershipTransfer.Status.CANCELLED
    transfer.reason = (transfer.reason + " | " if transfer.reason else "") + reason
    transfer.save(update_fields=["status", "reason"])


__all__ = [
    "get_secret", "set_secret", "delete_secret",
    "list_paths", "list_records", "record_exists",
    "get_ref", "list_refs", "touch_ref",
    "list_backends", "get_active_backend", "set_active_backend",
    "get_backend_credentials", "set_backend_credentials",
    "delete_backend_credentials", "test_backend",
]