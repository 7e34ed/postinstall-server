"""Абстрактные проверки прав.

Здесь только интерфейсы и безопасные дефолты.
Реальные реализации внедряются из apps.access при старте приложения
(см. apps/access/apps.py:ready).

Правило архитектуры:
  core     — не знает ни про access, ни про secrets;
  access   — знает про core (регистрирует себя как провайдера);
  secrets  — знает про core (использует интерфейс);
  никто из вышеперечисленных не импортирует друг друга напрямую.
"""
from __future__ import annotations

from collections.abc import Callable

_supervisor_checker: Callable | None = None


def register_supervisor_checker(fn: Callable[[object], bool]) -> None:
    """Внедрить реализацию is_supervisor.

    Вызывается один раз из access.apps.AccessConfig.ready.
    Идемпотентно: повторная регистрация перезаписывает.
    """
    global _supervisor_checker
    _supervisor_checker = fn


# AAL
_aal_requirement: Callable | None = None


def register_aal_requirement(fn: Callable[[str], int]) -> None:
    """Внедрить реализацию get_aal_requirement (из access.aal).

    fn(action: str) -> int (уровень AAL).
    """
    global _aal_requirement
    _aal_requirement = fn


def get_aal_requirement(action: str) -> int:
    """AAL для действия. Если провайдер не зарегистрирован — AAL1 (fail-safe)."""
    if _aal_requirement is None:
        return 1
    try:
        return int(_aal_requirement(action))
    except Exception:
        return 1


# Роли
_active_roles: Callable | None = None


def register_active_roles(fn: Callable[[object], set[str]]) -> None:
    """Внедрить реализацию get_user_roles (из access.permissions)."""
    global _active_roles
    _active_roles = fn


def get_user_roles(user) -> set[str]:
    """Активные роли пользователя. Если провайдер не зарегистрирован — set()."""
    if _active_roles is None:
        return set()
    try:
        return set(_active_roles(user))
    except Exception:
        return set()


def is_supervisor(user) -> bool:
    """Является ли пользователь SUPERVISOR'ом.

    Если access не загружен или пользователь не аутентифицирован —
    возвращает False (безопасный дефолт).
    """
    if _supervisor_checker is None:
        return False
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    try:
        return bool(_supervisor_checker(user))
    except Exception:
        return False


_user_max_aal: Callable | None = None


def register_user_max_aal(fn: Callable) -> None:
    global _user_max_aal
    _user_max_aal = fn


def user_max_aal(user) -> int:
    if _user_max_aal is None:
        return 1  # fail-safe
    try:
        return int(_user_max_aal(user))
    except Exception:
        return 1


_can_view_object: Callable | None = None
_can_deploy: Callable | None = None


def register_object_checkers(view_fn, deploy_fn) -> None:
    global _can_view_object, _can_deploy
    _can_view_object = view_fn
    _can_deploy = deploy_fn


def user_can_view_object(user, obj) -> bool:
    if _can_view_object is None:
        return False
    try:
        return bool(_can_view_object(user, obj))
    except Exception:
        return False


def user_can_deploy(user, *, host) -> bool:
    if _can_deploy is None:
        return False
    try:
        return bool(_can_deploy(user, host))
    except Exception:
        return False