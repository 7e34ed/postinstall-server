"""
DRF permissions на основе ролей и AAL.

Используются, если мы добавим REST API для UI (НЕ для агентов).
У агентов своя аутентификация (IsAgent).
"""

from __future__ import annotations

from rest_framework.permissions import BasePermission

from .aal import AAL, requirement_for_action
from .permissions import active_roles, user_can_edit_object
from .scopes import scope_for_object
from .session_aal import current_aal


class HasRoleInScope(BasePermission):
    """Проверяет, что у пользователя есть роль из allowed в scope объекта."""

    # Переопределяется в наследниках или через класс-атрибуты view
    allowed_roles: set[str] = set()

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        return bool(active_roles(request.user))

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        allowed = self.allowed_roles or set()
        if not allowed:
            return user_can_edit_object(request.user, obj)

        scope = scope_for_object(obj)
        for ra in active_roles(request.user):
            if ra.role not in allowed:
                continue
            from .permissions import _ra_covers_scope
            if scope.is_global:
                return True
            if _ra_covers_scope(ra, scope.scope_type, scope.scope_id):
                return True
        return False


class HasAAL(BasePermission):
    """Требует минимальный AAL, заданный через view.aal_required."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True

        action = getattr(view, "aal_action", None)
        if action:
            required = requirement_for_action(action)
        else:
            required = getattr(view, "aal_required", AAL.AAL1)

        have = current_aal(request)
        return have >= required