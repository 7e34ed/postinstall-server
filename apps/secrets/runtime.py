"""In-memory singleton с расшифрованным блобом.

Расшифрованный блоб живёт в памяти процесса. Мастер-ключ не сохраняется.
Unlock идемпотентен; если уже разблокировано — не делает ничего.

При использовании gunicorn с --preload: unlock() вызывается в master-процессе,
воркеры форкаются с готовым блобом. Без --preload каждый воркер делает
unlock() независимо.
"""
from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from typing import Any

from loguru import logger

from . import blob as blob_mod
from .backends.base import SecretBackendError, SecretNotFound


class SecretsSealed(RuntimeError):
    """Секреты недоступны: мастер-ключ не введён."""


@dataclass
class RuntimeStatus:
    state: str            # uninitialized | sealed | unsealed
    version: int = 0
    active_backend: str = ""
    secrets_count: int = 0
    pid: int = 0


class SecretsRuntime:
    """Singleton. Все методы потокобезопасны."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data: dict | None = None
        self._master_key_check: bytes | None = None   # для быстрой валидации
        self._argon2: blob_mod.Argon2Params | None = None

    # --- состояние ---

    def is_initialized(self) -> bool:
        """Есть ли запись ServerKey в БД."""
        from .models import ServerKey
        try:
            return ServerKey.objects.exists()
        except Exception:
            return False

    def is_unsealed(self) -> bool:
        return self._data is not None

    def status(self) -> RuntimeStatus:
        initialized = self.is_initialized()
        if not initialized:
            return RuntimeStatus(state="uninitialized", pid=os.getpid())
        with self._lock:
            if self._data is None:
                return RuntimeStatus(state="sealed", pid=os.getpid())
            return RuntimeStatus(
                state="unsealed",
                version=self._data.get("version", 0),
                active_backend=self._data.get("active_backend", "local"),
                secrets_count=len(self._data.get("secrets", {})),
                pid=os.getpid(),
            )

    # --- lifecycle ---

    def configure_argon2(self, params: blob_mod.Argon2Params) -> None:
        self._argon2 = params

    def unlock(self, master_key: str) -> None:
        """Расшифровать блоб. Идемпотентно.

        Если уже unsealed с тем же ключом — ничего не делает.
        Если ключ другой — перечитывает блоб и перезаписывает.
        """
        from .models import ServerKey

        with self._lock:
            try:
                sk = ServerKey.objects.get()
            except ServerKey.DoesNotExist as exc:
                raise SecretsSealed(
                    "ServerKey не создан. Выполните: manage.py secrets init"
                ) from exc

            salt = sk.salt_bytes
            kek = blob_mod.derive_kek(master_key, salt, self._argon2)
            try:
                data = blob_mod.decrypt_blob(sk.blob_bytes, kek)
            except blob_mod.BlobError as exc:
                logger.warning(f"secrets: unlock failed: {exc}")
                raise SecretsSealed("мастер-ключ неверный") from exc

            self._data = data
            self._master_key_check = kek
            logger.info(
                f"secrets: unsealed (pid={os.getpid()}, "
                f"version={data.get('version')}, "
                f"secrets={len(data.get('secrets', {}))})"
            )

    def seal(self) -> None:
        with self._lock:
            self._data = None
            self._master_key_check = None
            logger.info(f"secrets: sealed (pid={os.getpid()})")

    def try_auto_unlock(self) -> bool:
        """Попытка разблокировки при старте процесса.

        Возвращает True, если удалось. Никогда не падает.
        """
        if self._data is not None:
            return True
        if not self.is_initialized():
            logger.info("secrets: uninitialized (ServerKey отсутствует)")
            return False

        from .keysources import find_master_key, InteractiveDisabled

        try:
            key, source = find_master_key()
        except InteractiveDisabled:
            logger.warning(
                "secrets: sealed (мастер-ключ не найден в FILE/FD/ENV; "
                "интерактивный режим запрещён)"
            )
            return False
        except Exception as exc:
            logger.error(f"secrets: не удалось получить мастер-ключ: {exc}")
            return False

        try:
            self.unlock(key)
            logger.info(f"secrets: master key obtained from {source}")
            return True
        except SecretsSealed as exc:
            logger.error(f"secrets: auto-unlock failed: {exc}")
            return False

    # --- доступ к данным ---

    def _require(self) -> dict:
        if self._data is None:
            raise SecretsSealed("secrets не разблокированы")
        return self._data

    def get(self, path: str, key: str) -> str:
        d = self._require()
        node: Any = d.get("secrets", {})
        for part in path.split("/"):
            if not isinstance(node, dict) or part not in node:
                raise SecretNotFound(f"{path}:{key} не найден")
            node = node[part]
        if not isinstance(node, dict) or key not in node:
            raise SecretNotFound(f"{path}:{key} не найден")
        return str(node[key])

    def set(self, path: str, key: str, value: str) -> None:
        with self._lock:
            d = self._require()
            node = d.setdefault("secrets", {})
            for part in path.split("/"):
                node = node.setdefault(part, {})
            node[key] = value

    def delete(self, path: str) -> None:
        with self._lock:
            d = self._require()
            parts = path.split("/")
            node = d.get("secrets", {})
            for part in parts[:-1]:
                node = node.get(part, {})
                if not isinstance(node, dict):
                    return
            node.pop(parts[-1], None)

    def exists(self, path: str) -> bool:
        try:
            self._require()
        except SecretsSealed:
            return False
        d = self._data or {}
        node: Any = d.get("secrets", {})
        for part in path.split("/"):
            if not isinstance(node, dict) or part not in node:
                return False
            node = node[part]
        return isinstance(node, dict) and bool(node)

    def list_paths(self) -> list[str]:
        d = self._require()
        out: list[str] = []

        def walk(node: dict, prefix: str) -> None:
            for k, v in node.items():
                full = f"{prefix}/{k}" if prefix else k
                if isinstance(v, dict):
                    # если все значения — скаляры, это лист
                    if all(not isinstance(x, dict) for x in v.values()):
                        out.append(full)
                    else:
                        walk(v, full)

        walk(d.get("secrets", {}), "")
        return sorted(out)

    # --- backend-credentials ---

    def get_backend_credentials(self, name: str) -> dict:
        d = self._require()
        return dict(d.get("backend_credentials", {}).get(name, {}))

    def set_backend_credentials(self, name: str, values: dict) -> None:
        with self._lock:
            d = self._require()
            d.setdefault("backend_credentials", {})[name] = dict(values)

    def get_active_backend(self) -> str:
        d = self._require()
        return d.get("active_backend", "local")

    def set_active_backend(self, name: str) -> None:
        with self._lock:
            d = self._require()
            d["active_backend"] = name

    # --- persist ---

    def persist(self) -> None:
        """Перешифровать текущий блоб и сохранить в БД."""
        from .models import ServerKey

        with self._lock:
            if self._data is None or self._master_key_check is None:
                raise SecretsSealed("нечего сохранять — secrets sealed")
            sk = ServerKey.objects.get()
            sk.blob_bytes = blob_mod.encrypt_blob(self._data, self._master_key_check)
            sk.save(update_fields=["blob", "updated_at"])

    def rotate_master_key(self, old_key: str, new_key: str) -> None:
        """Сменить мастер-ключ, перешифровать блоб."""
        from .models import ServerKey

        with self._lock:
            sk = ServerKey.objects.get()
            old_kek = blob_mod.derive_kek(old_key, sk.salt_bytes, self._argon2)
            try:
                data = blob_mod.decrypt_blob(sk.blob_bytes, old_kek)
            except blob_mod.BlobError as exc:
                raise SecretsSealed("старый мастер-ключ неверный") from exc

            new_salt = blob_mod.new_salt()
            new_kek = blob_mod.derive_kek(new_key, new_salt, self._argon2)
            new_blob = blob_mod.encrypt_blob(data, new_kek)

            import base64

            from django.utils import timezone
            
            sk.salt = base64.b64encode(new_salt).decode()
            sk.blob = base64.b64encode(new_blob).decode()
            sk.rotated_at = timezone.now()
            sk.save(update_fields=["salt", "blob", "rotated_at", "updated_at"])

            self._data = data
            self._master_key_check = new_kek
            logger.info("secrets: master key rotated")


runtime = SecretsRuntime()