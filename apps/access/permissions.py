from __future__ import annotations

from typing import Iterable

from django.contrib.auth.models import AnonymousUser
from django.utils import timezone

from .models import DeputyAssignment, RoleAssignment
from .roles import Role, ScopeType

CAN_MANAGE: dict[str, set[str]] = {
    Role.SUPERVISOR.value: {
        Role.ADMIN.value,
        Role.AUDITOR.value,
        Role.OPERATOR.value,
        Role.VIEWER.value,
    },
    Role.ADMIN.value: {
        Role.OPERATOR.value,
        Role.VIEWER.value,
    },
}

# --- Базовые ---

def active_roles(user) -> list[RoleAssignment]:
    if not user or isinstance(user, AnonymousUser) or not user.is_authenticated:
        return []
    now = timezone.now()
    qs = RoleAssignment.objects.filter(
        user=user, revoked_at__isnull=True,
    )
    result = []
    for ra in qs:
        if ra.valid_until and ra.valid_until < now:
            continue
        result.append(ra)
    return result


def user_has_role(
    user, role: Role | str, *,
    scope_type: ScopeType | str | None = None,
    scope_id: int | None = None,
) -> bool:
    role_v = role.value if isinstance(role, Role) else role
    for ra in active_roles(user):
        if ra.role != role_v:
            continue
        if scope_type is not None:
            st = scope_type.value if isinstance(scope_type, ScopeType) else scope_type
            if ra.scope_type != st:
                continue
        if scope_id is not None and ra.scope_id != scope_id:
            continue
        return True
    return False


def is_supervisor(user) -> bool:
    return user_has_role(user, Role.SUPERVISOR)


def is_admin_in(user, *, domain_id: int | None = None,
                host_set_id: int | None = None, host_id: int | None = None) -> bool:
    if user_has_role(user, Role.ADMIN, scope_type=ScopeType.GLOBAL):
        return True
    if domain_id is not None and user_has_role(
        user, Role.ADMIN, scope_type=ScopeType.DOMAIN, scope_id=domain_id,
    ):
        return True
    if host_set_id is not None and user_has_role(
        user, Role.ADMIN, scope_type=ScopeType.HOST_SET, scope_id=host_set_id,
    ):
        return True
    if host_id is not None and user_has_role(
        user, Role.ADMIN, scope_type=ScopeType.HOST, scope_id=host_id,
    ):
        return True
    return False


# --- Более высокоуровневые ---

def user_can_write(user, *, domain_id=None, host_set_id=None,
                   host_id=None) -> bool:
    """Может ли пользователь изменять объекты в указанном scope.

    SUPERVISOR сам по себе не даёт права записи, но может совмещаться
    с ADMIN на конкретном домене — тогда в этом домене пишет.
    """
    return is_admin_in(user, domain_id=domain_id, host_set_id=host_set_id,
                       host_id=host_id)


def user_can_read_secrets(user, *, domain_id=None) -> bool:
    """Секреты читает только ADMIN своего домена.

    SUPERVISOR — не читает никогда, даже если совмещён с ADMIN другого
    домена: чтение секретов требует ADMIN именно этого домена.
    """
    if not domain_id:
        return False
    return is_admin_in(user, domain_id=domain_id)


def user_can_invite(user, role: Role | str, *,
                    scope_type: ScopeType | str,
                    scope_id: int) -> bool:
    """Кто каких кандидатов может приглашать."""
    from .roles import ADMIN_CAN_INVITE, SUPERVISOR_CAN_INVITE
    
    role_v = role.value if isinstance(role, Role) else role

    # SUPERVISOR приглашает ADMIN'ов
    if user_has_role(user, Role.SUPERVISOR):
        if role_v in {r.value for r in SUPERVISOR_CAN_INVITE}:
            return True
        # SUPERVISOR также может приглашать младших ролей
        if role_v in {r.value for r in ADMIN_CAN_INVITE}:
            return True

    # ADMIN приглашает младших в своём домене
    if role_v in {r.value for r in ADMIN_CAN_INVITE}:
        st = scope_type.value if isinstance(scope_type, ScopeType) else scope_type
        if st in (ScopeType.DOMAIN.value, ScopeType.HOST_SET.value,
                  ScopeType.HOST.value):
            return is_admin_in(
                user,
                domain_id=scope_id if st == ScopeType.DOMAIN.value else None,
                host_set_id=scope_id if st == ScopeType.HOST_SET.value else None,
                host_id=scope_id if st == ScopeType.HOST.value else None,
            )
    return False


# --- Апруверы для consensus-инвайтов ---

def get_active_supervisors() -> list:
    from django.contrib.auth import get_user_model

    User = get_user_model()
    now = timezone.now()
    ra_qs = RoleAssignment.objects.filter(
        role=Role.SUPERVISOR.value, revoked_at__isnull=True,
    )
    user_ids = []
    for ra in ra_qs:
        if ra.valid_until and ra.valid_until < now:
            continue
        user_ids.append(ra.user_id)
    return list(User.objects.filter(pk__in=user_ids, is_active=True).distinct())


def get_elevated_deputies() -> list:
    """Заместители, для которых ELEVATED-режим активен сейчас."""
    result = []
    for dep in DeputyAssignment.objects.filter(
        kind=DeputyAssignment.Kind.ELEVATED,
        is_active=True,
    ).select_related("principal", "deputy"):
        if dep.is_currently_elevated():
            result.append(dep)
    return result


def get_approvers_for(invitation) -> list:
    """Кто может подтвердить конкретный инвайт.

    Все активные SUPERVISOR'ы + активные ELEVATED-заместители.
    Исключается invited_by.
    """
    users = list(get_active_supervisors())
    for dep in get_elevated_deputies():
        users.append(dep.deputy)
    # уникализируем
    seen = set()
    result = []
    for u in users:
        if u.pk in seen:
            continue
        seen.add(u.pk)
        if u.pk == invitation.invited_by_id:
            continue
        result.append(u)
    return result


def _ra_covers_scope(ra: RoleAssignment, scope_type: str, scope_id: int) -> bool:
    if ra.scope_type == ScopeType.GLOBAL.value:
        return True
    if ra.scope_type == scope_type and ra.scope_id == scope_id:
        return True
    if ra.scope_type == ScopeType.DOMAIN.value:
        if scope_type == ScopeType.HOST_SET.value:
            from apps.core.utils import resolve_scope_object

            hs = resolve_scope_object("host_set", scope_id)
            return hs is not None and hs.domain_id == ra.scope_id
        if scope_type == ScopeType.HOST.value:
            from apps.core.utils import resolve_scope_object

            h = resolve_scope_object("host", scope_id)
            return h is not None and h.domain_id == ra.scope_id
    if ra.scope_type == ScopeType.HOST_SET.value:
        if scope_type == ScopeType.HOST.value:
            from apps.core.utils import resolve_scope_object
            
            h = resolve_scope_object("host", scope_id)
            return h is not None and h.host_set_id == ra.scope_id
    return False


def _scope_covers(manager, scope_type: str, scope_id: int) -> bool:
    return any(_ra_covers_scope(ra, scope_type, scope_id)
               for ra in active_roles(manager))


# ============================================================
#  Иерархия управления ролями
# ============================================================

CAN_MANAGE: dict[str, set[str]] = {
    Role.SUPERVISOR.value: {
        Role.ADMIN.value,
        Role.AUDITOR.value,
        Role.OPERATOR.value,
        Role.VIEWER.value,
    },
    Role.ADMIN.value: {
        Role.OPERATOR.value,
        Role.VIEWER.value,
    },
}


def _ra_covers_scope(ra: RoleAssignment, scope_type: str, scope_id: int) -> bool:
    if ra.scope_type == ScopeType.GLOBAL.value:
        return True
    if ra.scope_type == scope_type and ra.scope_id == scope_id:
        return True
    if ra.scope_type == ScopeType.DOMAIN.value:
        if scope_type == ScopeType.HOST_SET.value:
            from apps.inventory.models import HostSet
            hs = HostSet.objects.filter(pk=scope_id).first()
            return hs is not None and hs.domain_id == ra.scope_id
        if scope_type == ScopeType.HOST.value:
            from apps.inventory.models import Host
            h = Host.objects.filter(pk=scope_id).first()
            return h is not None and h.domain_id == ra.scope_id
    if ra.scope_type == ScopeType.HOST_SET.value:
        if scope_type == ScopeType.HOST.value:
            from apps.inventory.models import Host
            h = Host.objects.filter(pk=scope_id).first()
            return h is not None and h.host_set_id == ra.scope_id
    return False


def can_manage_role(
    manager, target_role: str, *,
    scope_type: str, scope_id: int,
) -> bool:
    """Может ли manager выдавать/отзывать target_role в указанном scope."""
    if not manager or not getattr(manager, "is_authenticated", False):
        return False
    if manager.is_superuser:
        return True

    for ra in active_roles(manager):
        allowed = CAN_MANAGE.get(ra.role, set())
        if target_role not in allowed:
            continue
        if not _ra_covers_scope(ra, scope_type, scope_id):
            continue
        return True
    return False


def roles_user_can_manage(manager, *, scope_type: str, scope_id: int) -> set[str]:
    """Список ролей, которые manager может выдавать в этом scope."""
    if manager.is_superuser:
        return {r.value for r in Role if r != Role.SERVICE}

    result: set[str] = set()
    for ra in active_roles(manager):
        allowed = CAN_MANAGE.get(ra.role, set())
        if not _ra_covers_scope(ra, scope_type, scope_id):
            continue
        result.update(allowed)
    return result


# ============================================================
#  Универсальные проверки объекта
# ============================================================

def user_can_view_object(user, obj) -> bool:
    """Может ли пользователь видеть объект.

    Правила:
      * superuser — да;
      * SUPERVISOR — да (кроме секретов, но там отдельная проверка);
      * ADMIN в scope — да;
      * OPERATOR/VIEWER/AUDITOR в scope — да.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True

    from .scopes import scope_for_object

    scope = scope_for_object(obj)

    # GLOBAL: смотреть может любая аутентифицированная роль
    if scope.is_global:
        return bool(active_roles(user))

    for ra in active_roles(user):
        if _ra_covers_scope(ra, scope.scope_type, scope.scope_id):
            return True
    return False


def user_can_edit_object(user, obj) -> bool:
    """Может ли пользователь изменять объект.

    Только ADMIN в scope (или выше). OPERATOR может менять только
    deployments, через отдельное правило user_can_deploy.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True

    from .scopes import scope_for_object

    scope = scope_for_object(obj)
    if scope.is_global:
        # Глобальные объекты (профили, репозитории) — только ADMIN и выше.
        # Младшие роли их видят, но не редактируют.
        for ra in active_roles(user):
            if ra.role in (Role.SUPERVISOR.value, Role.ADMIN.value):
                return True
        return False

    return is_admin_in(
        user,
        domain_id=scope.domain_id,
        host_set_id=scope.host_set_id,
        host_id=scope.host_id,
    )


def user_can_delete_object(user, obj) -> bool:
    """Удалять может тот, кто редактирует. Исключения — в самих view."""
    return user_can_edit_object(user, obj)


def user_can_deploy(user, *, host) -> bool:
    """Может ли пользователь запускать деплой на хост.

    OPERATOR+ в scope хоста.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True

    for ra in active_roles(user):
        if ra.role not in (Role.SUPERVISOR.value, Role.ADMIN.value,
                           Role.OPERATOR.value):
            continue
        if _ra_covers_scope(ra, ScopeType.HOST.value, host.pk):
            return True
        if _ra_covers_scope(ra, ScopeType.HOST_SET.value, host.host_set_id):
            return True
        if _ra_covers_scope(ra, ScopeType.DOMAIN.value, host.domain_id):
            return True
    return False


def user_can_view_secrets_metadata(user) -> bool:
    """Видеть список секретов (без значений)."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    return bool(active_roles(user))
