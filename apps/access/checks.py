from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction

from .models import RoleAssignment
from .roles import Role, ScopeType


class InvariantViolation(ValidationError):
    pass


def count_active_supervisors(exclude_ids=None) -> int:
    qs = RoleAssignment.objects.filter(
        role=Role.SUPERVISOR.value,
        revoked_at__isnull=True,
    )
    if exclude_ids:
        qs = qs.exclude(pk__in=exclude_ids)
    return qs.values("user_id").distinct().count()


def assert_min_supervisors(*, excluding_ids=None, message: str = ""):
    """Гарантирует, что активных SUPERVISOR'ов ≥2 (с учётом изменения)."""
    n = count_active_supervisors(exclude_ids=excluding_ids)
    if n < 2:
        raise InvariantViolation(
            message or (
                "В системе должно быть не менее двух активных SUPERVISOR'ов. "
                f"Текущее количество (с учётом изменения): {n}."
            )
        )


def assert_can_revoke(assignment: RoleAssignment):
    """Проверка, что отзыв не нарушит инварианты."""
    if assignment.role == Role.SUPERVISOR.value:
        assert_min_supervisors(
            excluding_ids=[assignment.pk],
            message=(
                "Нельзя отозвать роль SUPERVISOR: останется меньше двух. "
                "Сначала назначьте второго SUPERVISOR'а."
            ),
        )


def assert_scope_valid(scope_type: str, scope_id: int):
    """Проверка, что scope_id ссылается на существующий объект."""
    if scope_type == ScopeType.GLOBAL:
        if scope_id != 0:
            raise InvariantViolation("GLOBAL требует scope_id=0")
        return
    # Импортируем лениво
    if scope_type == ScopeType.DOMAIN:
        from apps.inventory.models import Domain
        
        if not Domain.objects.filter(pk=scope_id).exists():
            raise InvariantViolation(f"Domain {scope_id} не найден")
    elif scope_type == ScopeType.HOST_SET:
        from apps.inventory.models import HostSet
        
        if not HostSet.objects.filter(pk=scope_id).exists():
            raise InvariantViolation(f"HostSet {scope_id} не найден")
    elif scope_type == ScopeType.HOST:
        from apps.inventory.models import Host
        
        if not Host.objects.filter(pk=scope_id).exists():
            raise InvariantViolation(f"Host {scope_id} не найден")
    else:
        raise InvariantViolation(f"неизвестный scope_type: {scope_type}")