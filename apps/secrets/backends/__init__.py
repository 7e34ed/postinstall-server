from __future__ import annotations

from .base import SecretBackend, SecretBackendError, SecretNotFound

BACKEND_CLASSES: dict[str, type[SecretBackend]] = {}


def _register() -> None:
    from .keepass import KeepassBackend
    from .local import LocalBackend
    from .openbao import OpenBaoBackend
    
    BACKEND_CLASSES.update({
        "local": LocalBackend,
        "openbao": OpenBaoBackend,
        "keepass": KeepassBackend,
    })


def is_registered(name: str) -> bool:
    if not BACKEND_CLASSES:
        _register()
    return name in BACKEND_CLASSES


def get_backend(name: str | None = None) -> SecretBackend:
    if not BACKEND_CLASSES:
        _register()

    if name is None:
        from ..runtime import runtime
        name = runtime.get_active_backend()

    cls = BACKEND_CLASSES.get(name)
    if cls is None:
        raise SecretBackendError(f"неизвестный backend: {name!r}")
    return cls()


__all__ = [
    "SecretBackend", "SecretBackendError", "SecretNotFound",
    "BACKEND_CLASSES", "get_backend", "is_registered",
]