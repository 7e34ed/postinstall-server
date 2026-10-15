"""Поиск мастер-ключа при старте процесса.

Порядок: FILE → FD → ENV → (опционально) интерактивный prompt.
Интерактивный prompt запрещён, если SECRETS_ALLOW_INTERACTIVE=False
(по умолчанию — запрещён; включается только для dev).

Возвращает (key, source) — key без завершающего \n и пробелов.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


class InteractiveDisabled(RuntimeError):
    pass


class MasterKeyNotFound(RuntimeError):
    pass


def _clean(s: str) -> str:
    return s.strip().rstrip("\n").rstrip("\r")


def from_file() -> tuple[str, str] | None:
    from django.conf import settings

    path = getattr(settings, "SECRETS_MASTER_KEY_FILE", "")
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        raise MasterKeyNotFound(f"SECRETS_MASTER_KEY_FILE={path} не найден")
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        raise MasterKeyNotFound(
            f"файл {path} имеет права {oct(mode)} — "
            "требуется 0600"
        )
    return _clean(p.read_text(encoding="utf-8")), f"file:{path}"


def from_fd() -> tuple[str, str] | None:
    from django.conf import settings
    
    fd = getattr(settings, "SECRETS_MASTER_KEY_FD", 0)
    if not fd or fd < 3:
        return None
    try:
        with os.fdopen(fd, "r", closefd=False) as f:
            return _clean(f.read()), f"fd:{fd}"
    except OSError as exc:
        raise MasterKeyNotFound(f"не удалось прочитать fd={fd}: {exc}") from exc


def from_env() -> tuple[str, str] | None:
    from django.conf import settings

    key = getattr(settings, "SECRETS_MASTER_KEY", "")
    if not key:
        return None
    import sys as _sys
    print(
        "WARNING: мастер-ключ получен из SECRETS_MASTER_KEY (env). "
        "Используйте SECRETS_MASTER_KEY_FILE или FD в проде.",
        file=_sys.stderr,
    )
    return _clean(key), "env"


def from_tty() -> tuple[str, str] | None:
    from django.conf import settings
    
    if not getattr(settings, "SECRETS_ALLOW_INTERACTIVE", False):
        raise InteractiveDisabled()
    if not sys.stdin.isatty():
        raise InteractiveDisabled()
    import getpass
    key = getpass.getpass("Мастер-ключ: ")
    if not key:
        raise MasterKeyNotFound("пустой ввод")
    return _clean(key), "tty"


def find_master_key() -> tuple[str, str]:
    for src in (from_file, from_fd, from_env, from_tty):
        result = src()
        if result is not None:
            return result
    raise MasterKeyNotFound("мастер-ключ не найден во всех источниках")