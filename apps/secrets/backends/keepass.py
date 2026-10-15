"""KeePass-бэкенд через pykeepass.

Маппинг path:key на структуру KeePass:
  path = "domains/example.local/domain_password"
      → группа domains/example.local, запись с title=domain_password
  key  = "password" | "username" | "url" | "notes" | "value"
      → стандартное свойство записи или custom property "value"

Доступ к файлу сериализован через файловый лок. Запись атомарная.
Перед каждой записью создаётся snapshot в backup_dir с retention.

Ограничения (см. docs/keepass.md):
  * рекомендуется до ~200 секретов и ~50 хостов;
  * один экземпляр приложения пишущий одновременно — то есть
    использование за LB+VRRP с несколькими подами требует
    read-only режима или внешней блокировки (S3/Redis-lock);
  * параллельная запись из нескольких процессов не поддерживается.
"""
from __future__ import annotations

from pathlib import Path

from loguru import logger
from pykeepass import PyKeePass  # noqa: F401  (для аннотаций)

from ..keepass_helpers import (
    KeepassError,
    KeepassParams,
    atomic_save,
    get_cached,
    invalidate_cache,
    lock,
    snapshot,
    validate_keyfile,
    validate_path,
)
from .base import SecretBackend, SecretBackendError, SecretNotFound

RESERVED_KEYS = {"password", "username", "url", "notes"}
CUSTOM_PREFIX = "psi."


class KeepassBackend(SecretBackend):
    name = "keepass"

    # --------------------------------------------------------
    #  Инициализация
    # --------------------------------------------------------

    def __init__(self):
        from ..runtime import SecretsSealed, runtime

        try:
            creds = runtime.get_backend_credentials("keepass")
        except SecretsSealed as exc:
            raise SecretBackendError("keepass: runtime sealed") from exc

        path_str = (creds.get("kdbx_path") or "").strip()
        password = creds.get("password") or ""
        if not path_str or not password:
            raise SecretBackendError(
                "keepass: не заданы kdbx_path или password. "
                "Настройте через /admin/secrets/backend/."
            )

        kdbx_path = Path(path_str).expanduser().resolve(strict=False)
        try:
            validate_path(kdbx_path)
        except KeepassError as exc:
            raise SecretBackendError(f"keepass: {exc}") from exc

        keyfile_path = None
        kf_str = (creds.get("keyfile_path") or "").strip()
        if kf_str:
            keyfile_path = Path(kf_str).expanduser().resolve(strict=False)
            try:
                validate_keyfile(keyfile_path)
            except KeepassError as exc:
                raise SecretBackendError(f"keepass: {exc}") from exc

        backup_dir = None
        bd_str = (creds.get("backup_dir") or "").strip()
        if bd_str:
            backup_dir = Path(bd_str).expanduser().resolve(strict=False)

        def _int(name: str, default: int) -> int:
            raw = creds.get(name, "")
            try:
                return int(raw) if raw else default
            except ValueError:
                return default

        self.params = KeepassParams(
            kdbx_path=kdbx_path,
            password=password,
            keyfile_path=keyfile_path,
            backup_dir=backup_dir,
            backup_retention=_int("backup_retention", 10),
            cache_ttl=_int("cache_ttl", 300),
        )

    @classmethod
    def required_credentials(cls) -> list[dict]:
        return [
            {"key": "kdbx_path", "label": "Путь к .kdbx", "required": True,
             "placeholder": "/var/lib/postinstall/secrets.kdbx"},
            {"key": "password", "label": "Мастер-пароль .kdbx",
             "required": True, "secret": True},
            {"key": "keyfile_path",
             "label": "Keyfile (опционально, для composite key)",
             "required": False,
             "placeholder": "/etc/postinstall/secrets.key"},
            {"key": "backup_dir",
             "label": "Каталог снапшотов (по умолчанию рядом с .kdbx/backups)",
             "required": False},
            {"key": "backup_retention",
             "label": "Сколько снапшотов хранить", "required": False,
             "placeholder": "10"},
            {"key": "cache_ttl",
             "label": "Cache TTL (сек)", "required": False,
             "placeholder": "300"},
        ]

    # --------------------------------------------------------
    #  Публичное API
    # --------------------------------------------------------

    def get(self, path: str, key: str) -> str:
        kp = get_cached(self.params)
        entry = self._find_entry(kp, path)
        if entry is None:
            raise SecretNotFound(f"keepass:{path} не найден")
        value = self._read_property(entry, key)
        if value is None:
            raise SecretNotFound(f"keepass:{path}:{key} не найден")
        return value

    def set(self, path: str, key: str, value: str) -> None:
        with lock(self.params):
            snapshot(self.params)   # сохранить старое состояние
            kp = get_cached(self.params)

            group_path, entry_title = self._split_path(path)
            group = self._ensure_group(kp, group_path)
            entry = kp.find_entries(title=entry_title, group=group, first=True)
            if entry is None:
                entry = kp.add_entry(group, entry_title, "", "")
                logger.info(f"secrets.keepass: создана запись {path}")

            self._write_property(entry, key, value)

            try:
                atomic_save(kp, self.params)
            finally:
                invalidate_cache()

    def delete(self, path: str) -> None:
        with lock(self.params):
            snapshot(self.params)
            kp = get_cached(self.params)
            group_path, entry_title = self._split_path(path)
            group = self._find_group(kp, group_path)
            if group is None:
                return
            entry = kp.find_entries(title=entry_title, group=group, first=True)
            if entry is None:
                return
            kp.delete_entry(entry)
            # если группа осталась пустой — не удаляем, чтобы не путать админа
            try:
                atomic_save(kp, self.params)
                logger.info(f"secrets.keepass: удалена запись {path}")
            finally:
                invalidate_cache()

    def exists(self, path: str) -> bool:
        try:
            kp = get_cached(self.params)
        except KeepassError:
            return False
        return self._find_entry(kp, path) is not None

    def health(self) -> dict:
        try:
            kp = get_cached(self.params)
            # грубо считаем количество записей для индикации
            entries = len(kp.entries)
            groups = len(kp.groups)
            return {
                "status": "ok",
                "path": str(self.params.kdbx_path),
                "entries": entries,
                "groups": groups,
                "keyfile": bool(self.params.keyfile_path),
            }
        except KeepassError as exc:
            return {"status": "error", "detail": str(exc)}
        except Exception as exc:
            return {"status": "error", "detail": f"unexpected: {exc}"}

    # --------------------------------------------------------
    #  Внутреннее
    # --------------------------------------------------------

    @staticmethod
    def _split_path(path: str) -> tuple[str, str]:
        if not path or "/" not in path:
            raise KeepassError(
                f"keepass: path должен иметь вид group/subgroup/entry, "
                f"получено {path!r}"
            )
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            raise KeepassError(
                f"keepass: path должен содержать минимум одну группу "
                f"и имя записи, получено {path!r}"
            )
        return "/".join(parts[:-1]), parts[-1]

    @staticmethod
    def _find_group(kp: PyKeePass, group_path: str):
        group = kp.root_group
        for part in group_path.split("/"):
            subgroup = next(
                (g for g in group.subgroups if g.name == part), None,
            )
            if subgroup is None:
                return None
            group = subgroup
        return group

    @classmethod
    def _ensure_group(cls, kp: PyKeePass, group_path: str):
        group = kp.root_group
        for part in group_path.split("/"):
            subgroup = next(
                (g for g in group.subgroups if g.name == part), None,
            )
            if subgroup is None:
                subgroup = kp.add_group(group, part)
            group = subgroup
        return group

    @classmethod
    def _find_entry(cls, kp: PyKeePass, path: str):
        try:
            group_path, entry_title = cls._split_path(path)
        except KeepassError:
            return None
        group = cls._find_group(kp, group_path)
        if group is None:
            return None
        return kp.find_entries(title=entry_title, group=group, first=True)

    @staticmethod
    def _read_property(entry, key: str) -> str | None:
        if key in RESERVED_KEYS:
            v = getattr(entry, key, None)
            return str(v) if v is not None else None
        # custom property
        for prop in entry.custom_properties:
            if prop == f"{CUSTOM_PREFIX}{key}":
                return str(entry.get_custom_property(prop))
        return None

    @staticmethod
    def _write_property(entry, key: str, value: str) -> None:
        if key in RESERVED_KEYS:
            setattr(entry, key, value)
        else:
            entry.set_custom_property(f"{CUSTOM_PREFIX}{key}", value)

    def iter_secrets(self, prefix: str = ""):
        from ..keepass_helpers import KeepassError, get_cached

        try:
            kp = get_cached(self.params)
        except KeepassError as exc:
            logger.warning(f"keepass: iter_secrets: {exc}")
            return

        def walk(group, path_parts: list[str]):
            for entry in group.entries:
                entry_path = "/".join(path_parts + [entry.title])
                if prefix and not entry_path.startswith(prefix):
                    continue
                if entry.password:
                    yield entry_path, "password", str(entry.password)
                if entry.username:
                    yield entry_path, "username", str(entry.username)
                if entry.url:
                    yield entry_path, "url", str(entry.url)
                if entry.notes:
                    yield entry_path, "notes", str(entry.notes)
                for prop in entry.custom_properties:
                    if prop.startswith(CUSTOM_PREFIX):
                        key = prop[len(CUSTOM_PREFIX):]
                        try:
                            value = entry.get_custom_property(prop)
                        except Exception:
                            continue
                        yield entry_path, key, str(value)

            for sg in group.subgroups:
                yield from walk(sg, path_parts + [sg.name])

        yield from walk(kp.root_group, [])