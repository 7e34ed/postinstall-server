"""Уровни Authenticator Assurance Level и таблица требований.

AAL1 — один фактор (пароль).
AAL2 — два фактора (пароль + TOTP / recovery code).
AAL3 — два фактора, один hardware (WebAuthn / client cert / Rutoken).

Проверки строятся на сессии: при логине выставляется базовый AAL,
при reauthenticate — поднимается. Действие требует минимальный AAL.
"""
from __future__ import annotations

from enum import IntEnum

from django.conf import settings
from loguru import logger


class AAL(IntEnum):
    NONE = 0
    AAL1 = 1
    AAL2 = 2
    AAL3 = 3

    @property
    def label(self) -> str:
        return {
            AAL.NONE: "не аутентифицирован",
            AAL.AAL1: "AAL1 (пароль)",
            AAL.AAL2: "AAL2 (пароль + TOTP)",
            AAL.AAL3: "AAL3 (пароль + hardware)",
        }[self]

    @classmethod
    def from_str(cls, s: str) -> "AAL":
        m = {
            "aal1": cls.AAL1,
            "aal2": cls.AAL2,
            "aal3": cls.AAL3,
        }
        return m.get((s or "").lower(), cls.NONE)


# ============================================================
#  Таблица «действие → минимальный AAL»
# ============================================================

# Ключ — префикс URL или логическое имя операции.
# Проверка идёт по префиксу: берётся самый специфичный матч.
AAL_REQUIREMENTS: dict[str, AAL] = {
    # Просмотры
    "/hosts/": AAL.AAL1,
    "/config/": AAL.AAL1,
    "/deploy/": AAL.AAL1,
    "/credentials/": AAL.AAL1,
    "/access/security/": AAL.AAL1,
    "/access/roles/": AAL.AAL2,     # список ролей — чувствительный

    # Модификации
    "/deploy/bulk/apply/": AAL.AAL2,
    "/deploy/drift/sync-all/": AAL.AAL2,
    "/config/profiles/new/": AAL.AAL2,
    "/config/profiles/": AAL.AAL2,
    "/credentials/new/": AAL.AAL3,
    "/access/roles/assign/": AAL.AAL3,

    # Секреты
    "/admin/secrets/items/": AAL.AAL2,
    "/admin/secrets/items/new/": AAL.AAL2,
    "/admin/secrets/backend/": AAL.AAL3,
    "/admin/secrets/migrations/": AAL.AAL2,
    "/admin/secrets/backend/set/": AAL.AAL3,
    "/admin/secrets/backend/credentials/": AAL.AAL3,
    "/admin/secrets/renew/": AAL.AAL3,

    # Особо критичное
    "/access/setup/": AAL.AAL1,     # setup доступен только superuser'у
}

# Логические операции (не по URL), для программных проверок
AAL_REQUIREMENTS_BY_ACTION: dict[str, AAL] = {
    "deploy.create": AAL.AAL2,
    "deploy.cancel": AAL.AAL2,
    "deploy.bulk": AAL.AAL2,
    "config.change": AAL.AAL2,
    "config.profile.change": AAL.AAL2,

    "secrets.read": AAL.AAL2,
    "secrets.write": AAL.AAL2,
    "secrets.backend.change": AAL.AAL3,
    "secrets.credentials.change": AAL.AAL3,
    "secrets.rotate_master": AAL.AAL3,

    "credentials.read": AAL.AAL3,
    "credentials.change": AAL.AAL3,

    "auth.invite_admin": AAL.AAL3,
    "auth.invite_supervisor": AAL.AAL3,
    "auth.change_role": AAL.AAL3,
    "auth.assign_role": AAL.AAL3,

    "high_security.toggle": AAL.AAL3,
}

# Типы факторов, которые засчитываются как hardware для AAL3
AAL3_HARDWARE_TYPES: set[str] = {
    "webauthn",
    "client_cert",
    "rutoken",
}


def requirement_for_path(path: str) -> AAL | None:
    """Минимальный AAL для URL. None — не регламентировано (AAL1)."""
    best_len = -1
    best: AAL | None = None
    for prefix, req in AAL_REQUIREMENTS.items():
        if path.startswith(prefix) and len(prefix) > best_len:
            best = req
            best_len = len(prefix)
    return best


def requirement_for_action(action: str) -> AAL:
    return AAL_REQUIREMENTS_BY_ACTION.get(action, AAL.AAL1)


def aal3_strict() -> bool:
    """Требовать ли жёстко hardware для AAL3.

    Пока WebAuthn/client cert не развёрнуты, включается fallback:
    AAL2 + двухстороннее подтверждение. По мере готовности
    AUTH_AAL3_STRICT=constance → True.

    Здесь используется settings (bootstrap), чтобы не зависеть
    от constance на уровне фреймворка.
    """
    try:
        from constance import config
        
        return bool(config.AUTH_AAL3_STRICT)
    except Exception:
        return False

def user_max_aal(user, request=None) -> AAL:
    """Максимальный AAL, достижимый пользователем сейчас.

    Учитывает: включён ли MFA, есть ли TOTP, есть ли hardware.
    """
    
    from .hardware import has_hardware_factor

    if user is None or not user.is_authenticated:
        return AAL.NONE

    if has_hardware_factor(user):
        return AAL.AAL3

    has_totp = False
    try:
        from allauth.mfa.models import Authenticator

        has_totp = Authenticator.objects.filter(
            user=user, type=Authenticator.Type.TOTP,
        ).exists()
    except Exception:
        pass

    if has_totp:
        return AAL.AAL2

    return AAL.AAL1