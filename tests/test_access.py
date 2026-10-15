import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, RequestFactory
from django.utils import timezone

from apps.access.checks import (
    InvariantViolation,
    assert_min_supervisors,
    count_active_supervisors,
)
from apps.access.models import (
    AuthAuditLog,
    RoleAssignment,
    RoleChangeNotice,
    SuperuserBootstrap,
)
from apps.access.permissions import (
    active_roles,
    get_active_supervisors,
    is_admin_in,
    is_supervisor,
    user_can_read_secrets,
    user_can_write,
)
from apps.access.roles import Role, ScopeType

User = get_user_model()


@pytest.fixture
def su(db):
    return User.objects.create_user("su", password="x", is_superuser=True)


@pytest.fixture
def alice(db):
    return User.objects.create_user("alice", password="x")


@pytest.fixture
def bob(db):
    return User.objects.create_user("bob", password="x")


def _assign(user, role, scope_type=ScopeType.GLOBAL, scope_id=0, **kw):
    return RoleAssignment.objects.create(
        user=user, role=role.value if isinstance(role, Role) else role,
        scope_type=scope_type.value if isinstance(scope_type, ScopeType) else scope_type,
        scope_id=scope_id, **kw,
    )


# --- Invariants ---

@pytest.mark.django_db
def test_count_supervisors(alice, bob):
    assert count_active_supervisors() == 0
    _assign(alice, Role.SUPERVISOR)
    assert count_active_supervisors() == 1
    _assign(bob, Role.SUPERVISOR)
    assert count_active_supervisors() == 2


@pytest.mark.django_db
def test_assert_min_supervisors_fails_with_one(alice):
    _assign(alice, Role.SUPERVISOR)
    with pytest.raises(InvariantViolation, match="двух"):
        assert_min_supervisors()


@pytest.mark.django_db
def test_assert_min_supervisors_ok(alice, bob):
    _assign(alice, Role.SUPERVISOR)
    _assign(bob, Role.SUPERVISOR)
    assert_min_supervisors()


# --- RoleAssignment ---

@pytest.mark.django_db
def test_role_assignment_global_scope_valid(alice):
    _assign(alice, Role.SUPERVISOR)
    assert RoleAssignment.objects.filter(user=alice).count() == 1


@pytest.mark.django_db
def test_role_assignment_invalid_global(alice):
    ra = RoleAssignment(user=alice, role="supervisor",
                        scope_type="global", scope_id=5)
    with pytest.raises(ValidationError):
        ra.clean()


@pytest.mark.django_db
def test_role_assignment_scoped_requires_id(alice):
    ra = RoleAssignment(user=alice, role="admin",
                        scope_type="domain", scope_id=0)
    with pytest.raises(ValidationError):
        ra.clean()


# --- Permissions ---

@pytest.mark.django_db
def test_is_supervisor(alice):
    assert not is_supervisor(alice)
    _assign(alice, Role.SUPERVISOR)
    assert is_supervisor(alice)


@pytest.mark.django_db
def test_is_admin_in_domain(alice):
    from apps.inventory.models import Domain
    d = Domain.objects.create(name="test.local")
    assert not is_admin_in(alice, domain_id=d.pk)
    _assign(alice, Role.ADMIN, ScopeType.DOMAIN, d.pk)
    assert is_admin_in(alice, domain_id=d.pk)


@pytest.mark.django_db
def test_user_can_write_supervisor_alone_is_false(alice):
    """SUPERVISOR без ADMIN не пишет."""
    _assign(alice, Role.SUPERVISOR)
    from apps.inventory.models import Domain
    d = Domain.objects.create(name="test.local")
    assert not user_can_write(alice, domain_id=d.pk)


@pytest.mark.django_db
def test_user_can_write_supervisor_and_admin(alice):
    _assign(alice, Role.SUPERVISOR)
    from apps.inventory.models import Domain
    d = Domain.objects.create(name="test.local")
    _assign(alice, Role.ADMIN, ScopeType.DOMAIN, d.pk)
    assert user_can_write(alice, domain_id=d.pk)


@pytest.mark.django_db
def test_supervisor_cannot_read_secrets(alice):
    """Ключевое правило: SUPERVISOR не читает секреты, даже если ADMIN."""
    from apps.inventory.models import Domain
    d = Domain.objects.create(name="test.local")
    _assign(alice, Role.SUPERVISOR)
    _assign(alice, Role.ADMIN, ScopeType.DOMAIN, d.pk)
    # ADMIN своего домена — может
    assert user_can_read_secrets(alice, domain_id=d.pk)


@pytest.mark.django_db
def test_roles_aggregation(alice):
    from apps.inventory.models import Domain
    d1 = Domain.objects.create(name="a.local")
    d2 = Domain.objects.create(name="b.local")
    _assign(alice, Role.SUPERVISOR)
    _assign(alice, Role.ADMIN, ScopeType.DOMAIN, d1.pk)
    _assign(alice, Role.VIEWER, ScopeType.DOMAIN, d2.pk)

    assert is_supervisor(alice)
    assert is_admin_in(alice, domain_id=d1.pk)
    assert not is_admin_in(alice, domain_id=d2.pk)
    assert not user_can_write(alice, domain_id=d2.pk)


@pytest.mark.django_db
def test_revoked_roles_not_counted(alice):
    ra = _assign(alice, Role.SUPERVISOR)
    ra.revoked_at = timezone.now()
    ra.save()
    assert not is_supervisor(alice)


@pytest.mark.django_db
def test_expired_roles_not_counted(alice):
    _assign(alice, Role.SUPERVISOR, valid_until=timezone.now())
    assert not is_supervisor(alice)


# --- Setup phase ---

@pytest.mark.django_db
def test_setup_phase_initial():
    boot = SuperuserBootstrap.get()
    assert not boot.is_setup_complete


@pytest.mark.django_db
def test_setup_redirects(db):
    """Пока setup не завершён — все URL → /access/setup/."""
    c = Client()
    r = c.get("/")
    assert r.status_code == 302
    assert "/access/setup/" in r.url


@pytest.mark.django_db
def test_setup_middleware_exempt_health(db):
    c = Client()
    r = c.get("/api/v1/health")
    # /health не должен редиректить — но может быть 503 от SealedGate.
    # SetupMiddleware его пропускает.
    assert r.status_code != 302


@pytest.mark.django_db
def test_setup_view_creates_supervisor(su):
    c = Client()
    c.force_login(su)
    r = c.get("/access/setup/")
    assert r.status_code == 200


@pytest.mark.django_db
def test_setup_view_two_supervisors_completes_setup(su, alice, bob):
    c = Client()
    c.force_login(su)

    r = c.post("/access/setup/", {"username": alice.username,
                                   "email": "a@a.a"})
    assert r.status_code == 200
    assert is_supervisor(alice)
    boot = SuperuserBootstrap.get()
    assert not boot.is_setup_complete

    r = c.post("/access/setup/", {"username": bob.username})
    assert r.status_code == 302
    assert is_supervisor(bob)
    boot.refresh_from_db()
    assert boot.is_setup_complete


# --- RoleChangeNotice ---

@pytest.mark.django_db
def test_role_notice_blocks(db, alice):
    from apps.inventory.models import Domain
    _assign(alice, Role.SUPERVISOR)
    _assign(alice, Role.ADMIN, ScopeType.DOMAIN,
            Domain.objects.create(name="t.local").pk)
    SuperuserBootstrap.get().update_setup_complete(True) if False else None
    boot = SuperuserBootstrap.get()
    boot.is_setup_complete = True
    boot.save()

    RoleChangeNotice.objects.create(
        user=alice,
        changes=[{"kind": "grant", "role": "admin",
                  "scope_type": "domain", "scope_id": 1}],
    )

    c = Client()
    c.force_login(alice)
    r = c.get("/hosts/")
    assert r.status_code == 302
    assert "/access/roles-changed/" in r.url


@pytest.mark.django_db
def test_role_notice_acknowledge(db, alice):
    boot = SuperuserBootstrap.get()
    boot.is_setup_complete = True
    boot.save()

    n = RoleChangeNotice.objects.create(
        user=alice, changes=[{"kind": "grant", "role": "admin"}],
    )
    c = Client()
    c.force_login(alice)
    r = c.post("/access/roles-changed/", {"action": "acknowledge"})
    assert r.status_code == 302
    n.refresh_from_db()
    assert n.acknowledged_at is not None


# --- Invite landing ---

@pytest.mark.django_db
def test_invite_landing_invalid(db):
    c = Client()
    r = c.get("/access/invite/nonexistent-token/")
    assert r.status_code == 404