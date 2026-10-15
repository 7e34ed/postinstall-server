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

from typing import Callable

_supervisor_checker: Callable | None = None


def register_supervisor_checker(fn: Callable[[object], bool]) -> None:
    """Внедрить реализацию is_supervisor.

    Вызывается один раз из access.apps.AccessConfig.ready.
    Идемпотентно: повторная регистрация перезаписывает.
    """
    global _supervisor_checker
    _supervisor_checker = fn


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