"""Добавляет в контекст шаблонов флаги прав."""
from __future__ import annotations


def access_flags(request):
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {
            "can_supervise": False,
            "can_admin_any": False,
            "can_operate_any": False,
            "can_view_secrets": False,
        }

    from .permissions import active_roles, is_supervisor
    from .roles import Role

    roles = {ra.role for ra in active_roles(user)}

    return {
        "can_supervise": is_supervisor(user) or user.is_superuser,
        "can_admin_any": (Role.ADMIN.value in roles) or user.is_superuser,
        "can_operate_any": (
            bool(roles & {Role.ADMIN.value, Role.OPERATOR.value})
            or user.is_superuser
        ),
        "can_view_secrets": bool(roles) or user.is_superuser,
    }