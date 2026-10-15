"""
Определение scope пользователя для дашборда и агрегаций.

Дашборд показывает сводку по парку. Для пользователя без глобальных
ролей — сводка по его scope (union по всем RoleAssignment).

Правила:
  * superuser                 → всё;
  * SUPERVISOR                → всё (только чтение, но дашборд — чтение);
  * ADMIN/OPERATOR/AUDITOR/VIEWER → union своих scope (DOMAIN/HOST_SET/HOST);
  * нет ролей                 → пусто.

Возвращаем Q-выражения, чтобы фильтры применялись в SQL, не в Python.
"""

from __future__ import annotations

from django.db.models import Q

from apps.access.permissions import active_roles
from apps.access.roles import Role, ScopeType


def _is_unrestricted(user) -> bool:
    """Пользователь видит всё: superuser или SUPERVISOR."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    return any(
        ra.role == Role.SUPERVISOR.value for ra in active_roles(user)
    )


def host_scope_q(user) -> Q:
    """Q-выражение для фильтрации Host.objects."""
    if _is_unrestricted(user):
        return Q()

    roles = active_roles(user)
    if not roles:
        return Q(pk__in=[])

    conditions = Q(pk__in=[])
    for ra in roles:
        if ra.scope_type == ScopeType.DOMAIN.value:
            conditions |= Q(domain_id=ra.scope_id)
        elif ra.scope_type == ScopeType.HOST_SET.value:
            conditions |= Q(host_set_id=ra.scope_id)
        elif ra.scope_type == ScopeType.HOST.value:
            conditions |= Q(pk=ra.scope_id)
        elif ra.scope_type == ScopeType.GLOBAL.value:
            # GLOBAL для не-SUPERVISOR редко, но трактуем как «всё»
            return Q()
    return conditions


def deployment_scope_q(user) -> Q:
    """Q-выражение для Deployment.objects (через Host)."""
    if _is_unrestricted(user):
        return Q()

    roles = active_roles(user)
    if not roles:
        return Q(pk__in=[])

    conditions = Q(pk__in=[])
    for ra in roles:
        if ra.scope_type == ScopeType.DOMAIN.value:
            conditions |= Q(host__domain_id=ra.scope_id)
        elif ra.scope_type == ScopeType.HOST_SET.value:
            conditions |= Q(host__host_set_id=ra.scope_id)
        elif ra.scope_type == ScopeType.HOST.value:
            conditions |= Q(host_id=ra.scope_id)
        elif ra.scope_type == ScopeType.GLOBAL.value:
            return Q()
    return conditions


def domain_scope_q(user) -> Q:
    """Q-выражение для Domain.objects."""
    if _is_unrestricted(user):
        return Q()

    roles = active_roles(user)
    if not roles:
        return Q(pk__in=[])

    domain_ids: set[int] = set()
    hostset_ids: list[int] = []
    host_ids: list[int] = []

    for ra in roles:
        if ra.scope_type == ScopeType.DOMAIN.value:
            domain_ids.add(ra.scope_id)
        elif ra.scope_type == ScopeType.HOST_SET.value:
            hostset_ids.append(ra.scope_id)
        elif ra.scope_type == ScopeType.HOST.value:
            host_ids.append(ra.scope_id)
        elif ra.scope_type == ScopeType.GLOBAL.value:
            return Q()

    q = Q(pk__in=list(domain_ids))
    if hostset_ids:
        q |= Q(sets__pk__in=hostset_ids)
    if host_ids:
        q |= Q(hosts__pk__in=host_ids)
    return q


def agent_scope_q(user) -> Q:
    """Q-выражение для Agent.objects (через Host)."""
    if _is_unrestricted(user):
        return Q()

    roles = active_roles(user)
    if not roles:
        return Q(pk__in=[])

    conditions = Q(pk__in=[])
    for ra in roles:
        if ra.scope_type == ScopeType.DOMAIN.value:
            conditions |= Q(host__domain_id=ra.scope_id)
        elif ra.scope_type == ScopeType.HOST_SET.value:
            conditions |= Q(host__host_set_id=ra.scope_id)
        elif ra.scope_type == ScopeType.HOST.value:
            conditions |= Q(host_id=ra.scope_id)
        elif ra.scope_type == ScopeType.GLOBAL.value:
            return Q()
    return conditions