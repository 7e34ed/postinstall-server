"""Крипто для единого зашифрованного блоба.

Мастер-ключ → KEK (Argon2id) → AES-GCM.
Соль хранится рядом с блобом, nonce — в начале ciphertext.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .backends.base import SecretBackendError

NONCE_SIZE = 12
SALT_SIZE = 16
KEY_SIZE = 32


@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 65536   # 64 MiB
    parallelism: int = 4
    hash_len: int = KEY_SIZE
    type: Type = Type.ID


class BlobError(SecretBackendError):
    pass


def derive_kek(master_key: str, salt: bytes, params: Argon2Params | None = None) -> bytes:
    if not master_key:
        raise BlobError("master key is empty")
    if len(salt) != SALT_SIZE:
        raise BlobError(f"salt must be {SALT_SIZE} bytes, got {len(salt)}")
    p = params or Argon2Params()
    try:
        return hash_secret_raw(
            secret=master_key.encode("utf-8"),
            salt=salt,
            time_cost=p.time_cost,
            memory_cost=p.memory_cost,
            parallelism=p.parallelism,
            hash_len=p.hash_len,
            type=p.type,
        )
    except Exception as exc:
        raise BlobError(f"argon2id failed: {exc}") from exc


def encrypt_blob(data: dict, kek: bytes) -> bytes:
    if len(kek) != KEY_SIZE:
        raise BlobError(f"kek must be {KEY_SIZE} bytes")
    try:
        plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BlobError(f"cannot serialize blob: {exc}") from exc
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(kek).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_blob(blob: bytes, kek: bytes) -> dict:
    if len(blob) < NONCE_SIZE + 16:
        raise BlobError("blob too short")
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        plaintext = AESGCM(kek).decrypt(nonce, ct, None)
    except Exception as exc:
        raise BlobError(
            "decrypt failed — wrong master key or corrupted blob"
        ) from exc
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BlobError(f"invalid blob payload: {exc}") from exc


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def empty_blob() -> dict:
    return {
        "version": 1,
        "active_backend": "local",
        "backend_credentials": {},
        "secrets": {},
    }