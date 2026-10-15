"""Утилиты для KeePass-бэкенда.

Всё, что не относится к смыслу «секрет», а относится к безопасной работе
с файлом .kdbx: валидация пути, атомарная запись, файловый лок, ротация
снапшотов, кэш открытой БД.
"""
from __future__ import annotations

import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from filelock import FileLock, Timeout
from loguru import logger

from .backends.base import SecretBackendError

# ------------------------------------------------------------
#  Пути, запрещённые для .kdbx
# ------------------------------------------------------------

FORBIDDEN_PREFIXES = (
    "/proc", "/sys", "/dev", "/run/user",
)

# Будем валидировать при инициализации бэкенда.
# Список webroot-каталогов подтягивается из settings лениво, чтобы
# избежать циклического импорта.


class KeepassError(SecretBackendError):
    pass


# ------------------------------------------------------------
#  Параметры
# ------------------------------------------------------------

@dataclass
class KeepassParams:
    kdbx_path: Path
    password: str
    keyfile_path: Path | None = None
    backup_dir: Path | None = None
    backup_retention: int = 10
    cache_ttl: int = 300
    lock_timeout: float = 15.0

    @property
    def effective_backup_dir(self) -> Path:
        return self.backup_dir or (self.kdbx_path.parent / "backups")

    @property
    def lock_path(self) -> Path:
        return self.kdbx_path.with_suffix(self.kdbx_path.suffix + ".lock")


# ------------------------------------------------------------
#  Валидация пути
# ------------------------------------------------------------

def _webroots() -> list[Path]:
    """Каталоги, куда писать .kdbx категорически нельзя."""
    from django.conf import settings

    roots: list[Path] = []
    for attr in ("STATIC_ROOT", "MEDIA_ROOT", "BASE_DIR"):
        v = getattr(settings, attr, None)
        if v:
            roots.append(Path(v).resolve())
    return roots


def validate_path(path: Path, *, allow_missing: bool = False) -> None:
    """Проверка, что путь годится для хранения .kdbx.

    * абсолютный;
    * не в /proc /sys /dev /run/user;
    * не в /tmp;
    * не в STATIC_ROOT / MEDIA_ROOT / BASE_DIR проекта.
    """
    if not path.is_absolute():
        raise KeepassError(f"kdbx_path должен быть абсолютным: {path}")

    resolved = path.resolve(strict=False)

    for prefix in FORBIDDEN_PREFIXES:
        if str(resolved).startswith(prefix + "/") or str(resolved) == prefix:
            raise KeepassError(f"kdbx_path в запрещённом каталоге: {prefix}")

    if str(resolved).startswith("/tmp/") or str(resolved) == "/tmp":
        raise KeepassError("kdbx_path не может быть в /tmp")

    for root in _webroots():
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise KeepassError(
            f"kdbx_path не может быть внутри проекта/webroot ({root})"
        )

    if not allow_missing and not resolved.exists():
        raise KeepassError(f"kdbx_path не существует: {resolved}")

    if resolved.exists():
        st = resolved.stat()
        if st.st_mode & 0o077:
            logger.warning(
                f"secrets.keepass: права на {resolved} = "
                f"{oct(st.st_mode & 0o777)} (ожидалось 0600)"
            )


def validate_keyfile(path: Path | None) -> None:
    if path is None:
        return
    if not path.is_absolute():
        raise KeepassError(f"keyfile_path должен быть абсолютным: {path}")
    if not path.exists():
        raise KeepassError(f"keyfile_path не существует: {path}")


# ------------------------------------------------------------
#  Лок
# ------------------------------------------------------------

class _Lock:
    """Контекст-менеджер поверх filelock."""

    def __init__(self, path: Path, timeout: float):
        self._lock = FileLock(str(path), timeout=timeout)

    def __enter__(self):
        try:
            self._lock.acquire()
        except Timeout as exc:
            raise KeepassError(
                f"не удалось получить блокировку на kdbx за "
                f"{self._lock.lock_file} (timeout)"
            ) from exc
        return self

    def __exit__(self, *exc_info):
        try:
            self._lock.release()
        except Exception:
            pass


def lock(params: KeepassParams) -> _Lock:
    return _Lock(params.lock_path, params.lock_timeout)


# ------------------------------------------------------------
#  Атомарная запись
# ------------------------------------------------------------

def atomic_save(kp, params: KeepassParams) -> None:
    """Сохранить pykeepass-базу атомарно.

    Последовательность:
      1. Сохранить в <path>.tmp.
      2. fsync(tmp).
      3. os.replace(tmp, path)  — атомарно.
      4. fsync(родительский каталог) — для durability на диске.
    """
    path = params.kdbx_path
    tmp = path.with_suffix(path.suffix + ".tmp")

    try:
        kp.save(str(tmp))
    except Exception as exc:
        raise KeepassError(f"не удалось сохранить .kdbx во временный файл: {exc}") from exc

    try:
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
    except OSError as exc:
        logger.warning(f"secrets.keepass: fsync на {tmp} не удался: {exc}")

    try:
        os.replace(tmp, path)
    except OSError as exc:
        raise KeepassError(f"os.replace({tmp} -> {path}) не удался: {exc}") from exc

    try:
        dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        # не критично, не все FS поддерживают fsync на каталоге
        pass


# ------------------------------------------------------------
#  Snapshot + retention
# ------------------------------------------------------------

_snapshot_pool = ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="kdbx-snapshot",
)
_snapshot_lock = threading.Lock()


def snapshot(params: KeepassParams) -> Path | None:
    """Асинхронный snapshot.

    Синхронно (быстро): копирование файла во временное имя.
    Асинхронно (не блокирует запись): chmod, rename в финальное имя,
    ротация старых снапшотов.
    """
    src = params.kdbx_path
    if not src.exists():
        return None

    bdir = params.effective_backup_dir
    bdir.mkdir(parents=True, exist_ok=True)

    # Уникальное имя: микросекунды + pid — чтобы исключить коллизии
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    tmp = bdir / f".tmp-{src.stem}.{ts}.{os.getpid()}{src.suffix}"
    final = bdir / f"{src.stem}.{ts}{src.suffix}"

    try:
        shutil.copy2(src, tmp)
    except OSError as exc:
        logger.error(f"secrets.keepass: snapshot copy failed: {exc}")
        return None

    _snapshot_pool.submit(_finalize_snapshot, tmp, final, params)
    return final


def _finalize_snapshot(tmp: Path, final: Path, params: KeepassParams) -> None:
    try:
        os.chmod(tmp, 0o600)
        os.replace(tmp, final)
        _rotate_snapshots(
            params.effective_backup_dir,
            params.kdbx_path.stem,
            params.kdbx_path.suffix,
            params.backup_retention,
        )
    except Exception:
        logger.exception(f"secrets.keepass: snapshot finalize failed for {final}")
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def shutdown_snapshot_pool(wait: bool = True) -> None:
    """Для тестов и graceful-shutdown."""
    _snapshot_pool.shutdown(wait=wait)


def _rotate_snapshots(bdir: Path, stem: str, suffix: str, keep: int) -> None:
    if keep <= 0:
        return
    candidates = sorted(
        bdir.glob(f"{stem}.*{suffix}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in candidates[keep:]:
        try:
            old.unlink()
            logger.debug(f"secrets.keepass: удалён старый snapshot {old.name}")
        except OSError:
            pass


# ------------------------------------------------------------
#  Кэш открытой БД (thread-local)
# ------------------------------------------------------------

_tls = threading.local()


@dataclass
class _CachedKp:
    kp: object
    mtime: float
    loaded_at: float


def get_cached(params: KeepassParams):
    """Вернуть открытую pykeepass-базу из кэша или открыть заново.

    Инвалидация:
      * mtime файла изменился;
      * кэш старше cache_ttl.
    """
    import pykeepass

    path = params.kdbx_path
    if not path.exists():
        raise KeepassError(f"kdbx не существует: {path}")

    current_mtime = path.stat().st_mtime
    cached: _CachedKp | None = getattr(_tls, "kp_cache", None)

    if cached is not None:
        if cached.mtime != current_mtime:
            cached = None
        elif time.monotonic() - cached.loaded_at > params.cache_ttl:
            cached = None

    if cached is None:
        try:
            kp = pykeepass.PyKeePass(
                str(path),
                password=params.password,
                keyfile=str(params.keyfile_path) if params.keyfile_path else None,
            )
        except Exception as exc:
            raise KeepassError(
                f"не удалось открыть .kdbx (проверьте пароль и keyfile): {exc}"
            ) from exc
        cached = _CachedKp(kp=kp, mtime=current_mtime, loaded_at=time.monotonic())
        _tls.kp_cache = cached

    return cached.kp


def invalidate_cache() -> None:
    _tls.kp_cache = None