import pytest
from django.contrib.auth import get_user_model

from apps.access.models import RoleAssignment, RoleChangeNotice
from apps.access.permissions import can_manage_role, roles_user_can_manage
from apps.access.roles import Role, ScopeType
from apps.inventory.models import Domain

User = get_user_model()


def _assign(user, role, scope_type=ScopeType.GLOBAL, scope_id=0, **kw):
    return RoleAssignment.objects.create(
        user=user,
        role=role.value if isinstance(role, Role) else role,
        scope_type=scope_type.value if isinstance(scope_type, ScopeType) else scope_type,
        scope_id=scope_id, **kw,
    )


@pytest.fixture
def d1(db):
    return Domain.objects.create(name="a.local")


@pytest.fixture
def d2(db):
    return Domain.objects.create(name="b.local")


@pytest.fixture
def su(db):
    return User.objects.create_user("su")


@pytest.fixture
def admin(db, d1):
    u = User.objects.create_user("admin")
    _assign(u, Role.ADMIN, ScopeType.DOMAIN, d1.pk)
    return u


@pytest.fixture
def admin_other(db, d2):
    u = User.objects.create_user("admin2")
    _assign(u, Role.ADMIN, ScopeType.DOMAIN, d2.pk)
    return u


# --- can_manage_role ---

@pytest.mark.django_db
def test_supervisor_manages_admin(su):
    _assign(su, Role.SUPERVISOR)
    assert can_manage_role(su, "admin",
                            scope_type="global", scope_id=0)


@pytest.mark.django_db
def test_supervisor_manages_auditor(su):
    _assign(su, Role.SUPERVISOR)
    assert can_manage_role(su, "auditor",
                            scope_type="global", scope_id=0)


@pytest.mark.django_db
def test_admin_cannot_manage_auditor(admin, d1):
    assert not can_manage_role(admin, "auditor",
                                scope_type="domain", scope_id=d1.pk)


@pytest.mark.django_db
def test_admin_can_manage_operator(admin, d1):
    assert can_manage_role(admin, "operator",
                            scope_type="domain", scope_id=d1.pk)


@pytest.mark.django_db
def test_admin_cannot_manage_other_domain(admin, d2):
    assert not can_manage_role(admin, "operator",
                                scope_type="domain", scope_id=d2.pk)


@pytest.mark.django_db
def test_admin_cannot_manage_admin(admin, d1):
    assert not can_manage_role(admin, "admin",
                                scope_type="domain", scope_id=d1.pk)


# --- roles_user_can_manage ---

@pytest.mark.django_db
def test_roles_list_supervisor(su):
    _assign(su, Role.SUPERVISOR)
    roles = roles_user_can_manage(su, scope_type="global", scope_id=0)
    assert "admin" in roles
    assert "auditor" in roles
    assert "operator" in roles
    assert "viewer" in roles
    assert "supervisor" not in roles


@pytest.mark.django_db
def test_roles_list_admin(admin, d1):
    roles = roles_user_can_manage(admin, scope_type="domain", scope_id=d1.pk)
    assert "operator" in roles
    assert "viewer" in roles
    assert "auditor" not in roles
    assert "admin" not in roles


# --- DirectRoleAssignment ---

@pytest.mark.django_db
def test_direct_assignment_operator_single_approval(admin, d1):
    from apps.access.services import initiate_direct_assignment
    target = User.objects.create_user("op1")

    da = initiate_direct_assignment(
        target_user=target, role="operator",
        scope_type="domain", scope_id=d1.pk,
        by_user=admin,
    )
    assert da.status == "executed"
    assert RoleAssignment.objects.filter(user=target, role="operator").exists()
    assert RoleChangeNotice.objects.filter(user=target).exists()


@pytest.mark.django_db
def test_direct_assignment_admin_dual(su, d1):
    """ADMIN требует 2 подтверждения."""
    from apps.access.services import (
        approve_direct_assignment, initiate_direct_assignment,
    )
    su2 = User.objects.create_user("su2")
    _assign(su, Role.SUPERVISOR)
    _assign(su2, Role.SUPERVISOR)

    target = User.objects.create_user("admin-new")

    da = initiate_direct_assignment(
        target_user=target, role="admin",
        scope_type="domain", scope_id=d1.pk,
        by_user=su,
    )
    assert da.status == "pending"
    assert not RoleAssignment.objects.filter(
        user=target, role="admin",
    ).exists()

    # второй SUPERVISOR подтверждает
    approve_direct_assignment(da, by_user=su2)
    da.refresh_from_db()
    assert da.status == "executed"
    assert RoleAssignment.objects.filter(
        user=target, role="admin",
    ).exists()


@pytest.mark.django_db
def test_direct_assignment_cannot_self_approve(su, d1):
    from apps.access.services import initiate_direct_assignment
    _assign(su, Role.SUPERVISOR)
    target = User.objects.create_user("x")

    da = initiate_direct_assignment(
        target_user=target, role="admin",
        scope_type="domain", scope_id=d1.pk,
        by_user=su,
    )

    from apps.access.services import approve_direct_assignment
    with pytest.raises(PermissionError, match="другой"):
        approve_direct_assignment(da, by_user=su)


# --- revoke_role с инвариантами ---

@pytest.mark.django_db
def test_revoke_supervisor_blocked_with_one(su):
    from apps.access.services import revoke_role
    _assign(su, Role.SUPERVISOR)

    ra = RoleAssignment.objects.get(user=su, role="supervisor")
    with pytest.raises(Exception, match="двух"):
        revoke_role(ra, by_user=su)


@pytest.mark.django_db
def test_revoke_supervisor_ok_with_two(su):
    from apps.access.services import revoke_role
    su2 = User.objects.create_user("su2")
    _assign(su, Role.SUPERVISOR)
    _assign(su2, Role.SUPERVISOR)

    ra = RoleAssignment.objects.get(user=su, role="supervisor")
    revoke_role(ra, by_user=su2)
    assert RoleAssignment.objects.filter(
        user=su, role="supervisor", revoked_at__isnull=True,
    ).count() == 0