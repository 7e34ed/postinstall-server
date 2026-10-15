"""OpenBao-бэкенд (Vault-compatible) через hvac.

Credentials читаются из runtime (записаны через UI или management-команду):
  url       — http(s)://openbao.internal:8200
  token     — hvs.xxx (root или AppRole-issued)
  mount     — KV mount point, по умолчанию "secret"
  namespace — опциональный Vault namespace (Enterprise)

Поддерживается периодический renew токена в фоне (если токен renew-абельный).
"""
from __future__ import annotations

from datetime import datetime, timedelta

import hvac
from loguru import logger

from .base import SecretBackend, SecretBackendError, SecretNotFound


class OpenBaoBackend(SecretBackend):
    name = "openbao"

    def __init__(self):
        from ..runtime import runtime, SecretsSealed

        try:
            creds = runtime.get_backend_credentials("openbao")
        except SecretsSealed as exc:
            raise SecretBackendError(
                "openbao: runtime sealed"
            ) from exc

        self._url = creds.get("url", "")
        self._token = creds.get("token", "")
        self._mount = creds.get("mount", "secret")
        self._namespace = creds.get("namespace", "")

        if not self._url or not self._token:
            raise SecretBackendError(
                "openbao: не заданы url или token. "
                "Настройте через админку или manage.py secrets backend credentials openbao"
            )

        self._client = hvac.Client(url=self._url, token=self._token)
        if self._namespace:
            self._client.adapter.namespace = self._namespace

        if not self._client.is_authenticated():
            raise SecretBackendError(
                "openbao: токен не принят сервером"
            )

    # --- credentials ---

    @classmethod
    def required_credentials(cls) -> list[dict]:
        return [
            {"key": "url", "label": "URL", "required": True,
             "placeholder": "https://openbao.internal:8200"},
            {"key": "token", "label": "Token", "required": True,
             "secret": True, "placeholder": "hvs.xxx"},
            {"key": "mount", "label": "KV mount", "required": False,
             "placeholder": "secret"},
            {"key": "namespace", "label": "Namespace", "required": False,
             "placeholder": ""},
        ]

    # --- KV v2 ---

    def get(self, path: str, key: str) -> str:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount,
            )
        except hvac.exceptions.InvalidPath as exc:
            raise SecretNotFound(f"openbao:{path} не найден") from exc
        except hvac.exceptions.VaultError as exc:
            raise SecretBackendError(f"openbao: {exc}") from exc

        data = resp.get("data", {}).get("data", {})
        if key not in data:
            raise SecretNotFound(f"openbao:{path}:{key} не найден")
        return data[key]

    def set(self, path: str, key: str, value: str) -> None:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount,
            )
            existing = resp.get("data", {}).get("data", {})
        except hvac.exceptions.InvalidPath:
            existing = {}

        existing[key] = value
        self._client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=existing, mount_point=self._mount,
        )

    def delete(self, path: str) -> None:
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point=self._mount,
            )
        except hvac.exceptions.InvalidPath:
            pass

    def exists(self, path: str) -> bool:
        try:
            self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount,
            )
            return True
        except hvac.exceptions.InvalidPath:
            return False
        except hvac.exceptions.VaultError:
            return False

    # --- health / renew ---

    def health(self) -> dict:
        try:
            h = self._client.sys.read_health_status(method="GET")
            body = h.json() if hasattr(h, "json") else {}
            sealed = bool(body.get("sealed", False))
            standby = bool(body.get("standby", False))

            if sealed:
                return {"status": "error", "detail": "sealed"}
            if h.status_code not in (200, 429, 472, 473):
                return {"status": "error", "detail": f"http {h.status_code}"}

            # проверяем token lookup
            try:
                info = self._client.auth.token.lookup_self()
                data = info.get("data", {})
                ttl = data.get("ttl", 0)
                renewable = data.get("renewable", False)
                return {
                    "status": "ok",
                    "sealed": False,
                    "standby": standby,
                    "token_ttl": ttl,
                    "renewable": renewable,
                }
            except hvac.exceptions.VaultError as exc:
                return {"status": "error", "detail": f"token lookup: {exc}"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

    def maybe_renew_token(self) -> dict | None:
        """Обновить токен, если скоро истечёт и он renewable.

        Возвращает dict с новой информацией или None.
        """
        try:
            info = self._client.auth.token.lookup_self()
        except hvac.exceptions.VaultError as exc:
            logger.warning(f"openbao: token lookup failed: {exc}")
            return None

        data = info.get("data", {})
        ttl = int(data.get("ttl", 0) or 0)
        renewable = bool(data.get("renewable", False))

        if not renewable:
            return None
        if ttl > 600:
            return None

        try:
            resp = self._client.auth.token.renew_self()
        except hvac.exceptions.VaultError as exc:
            logger.error(f"openbao: token renew failed: {exc}")
            return None

        new_ttl = resp.get("auth", {}).get("lease_duration", 0)
        logger.info(f"openbao: token renewed, new ttl {new_ttl}s")
        return {"ttl": new_ttl}

    def iter_secrets(self, prefix: str = ""):
        """Рекурсивно обходит KV v2 по указанному префиксу.

        OpenBao list возвращает "каталоги" (с "/" в конце) и записи.
        Для записей вызываем read_secret_version, для каталогов — рекурсия.
        """
        mount = self._mount
        client = self._client

        def list_at(path: str):
            try:
                resp = client.secrets.kv.v2.list_secrets(
                    path=path.rstrip("/"), mount_point=mount,
                )
            except hvac.exceptions.InvalidPath:
                return []
            except hvac.exceptions.VaultError as exc:
                logger.warning(f"openbao: list {path}: {exc}")
                return []
            return resp.get("data", {}).get("keys", [])

        def walk(path: str):
            for item in list_at(path):
                full = f"{path.rstrip('/')}/{item}" if path else item
                if item.endswith("/"):
                    yield from walk(full)
                    continue
                if prefix and not full.startswith(prefix):
                    continue
                try:
                    resp = client.secrets.kv.v2.read_secret_version(
                        path=full, mount_point=mount,
                    )
                except hvac.exceptions.VaultError as exc:
                    logger.warning(f"openbao: read {full}: {exc}")
                    continue
                data = resp.get("data", {}).get("data", {})
                for key, value in data.items():
                    yield full, key, str(value)

        yield from walk(prefix.rsplit("/", 1)[0] if "/" in prefix else "")