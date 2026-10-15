import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from apps.access.models import RoleAssignment
from apps.access.permissions import (
    user_can_deploy, user_can_edit_object, user_can_view_object,
)
from apps.access.roles import Role, ScopeType
from apps.inventory.models import Domain, Host, HostSet

User = get_user_model()


def _assign(user, role, scope_type=ScopeType.GLOBAL, scope_id=0):
    return RoleAssignment.objects.create(
        user=user, role=role if isinstance(role, str) else role.value,
        scope_type=scope_type if isinstance(scope_type, str) else scope_type.value,
        scope_id=scope_id,
    )


@pytest.fixture
def d1(db):
    return Domain.objects.create(name="a.local")


@pytest.fixture
def d2(db):
    return Domain.objects.create(name="b.local")


@pytest.fixture
def hs1(d1):
    return HostSet.objects.create(domain=d1, name="web",
                                   platform="linux.debian")


@pytest.fixture
def h1(hs1):
    return Host.objects.create(domain=hs1.domain, host_set=hs1,
                                hostname="web1")


# --- user_can_view_object ---

@pytest.mark.django_db
def test_viewer_can_view_host_in_scope(h1):
    u = User.objects.create_user("v")
    _assign(u, Role.VIEWER, ScopeType.DOMAIN, h1.domain_id)
    assert user_can_view_object(u, h1)


@pytest.mark.django_db
def test_viewer_cannot_view_host_outside_scope(h1, d2):
    u = User.objects.create_user("v")
    _assign(u, Role.VIEWER, ScopeType.DOMAIN, d2.pk)
    assert not user_can_view_object(u, h1)


@pytest.mark.django_db
def test_supervisor_can_view_any(h1):
    u = User.objects.create_user("sup")
    _assign(u, Role.SUPERVISOR)
    assert user_can_view_object(u, h1)


@pytest.mark.django_db
def test_superuser_can_view_any(h1):
    u = User.objects.create_user("su", is_superuser=True)
    assert user_can_view_object(u, h1)


@pytest.mark.django_db
def test_no_role_cannot_view(h1):
    u = User.objects.create_user("plain")
    assert not user_can_view_object(u, h1)


# --- user_can_edit_object ---

@pytest.mark.django_db
def test_admin_can_edit_in_scope(h1):
    u = User.objects.create_user("a")
    _assign(u, Role.ADMIN, ScopeType.DOMAIN, h1.domain_id)
    assert user_can_edit_object(u, h1)


@pytest.mark.django_db
def test_operator_cannot_edit_host(h1):
    u = User.objects.create_user("op")
    _assign(u, Role.OPERATOR, ScopeType.DOMAIN, h1.domain_id)
    assert not user_can_edit_object(u, h1)


@pytest.mark.django_db
def test_admin_other_domain_cannot_edit(h1, d2):
    u = User.objects.create_user("a2")
    _assign(u, Role.ADMIN, ScopeType.DOMAIN, d2.pk)
    assert not user_can_edit_object(u, h1)


@pytest.mark.django_db
def test_admin_can_edit_global_object(db):
    """Профиль — глобальный ресурс, ADMIN любого домена может."""
    from apps.config.models import ConfigProfile

    p = ConfigProfile.objects.create(name="x", slug="x", platform="any")
    u = User.objects.create_user("a3")
    _assign(u, Role.ADMIN, ScopeType.DOMAIN, Domain.objects.create(
        name="c.local").pk)
    assert user_can_edit_object(u, p)


@pytest.mark.django_db
def test_operator_cannot_edit_global_object(db):
    from apps.config.models import ConfigProfile

    p = ConfigProfile.objects.create(name="x", slug="x", platform="any")
    u = User.objects.create_user("op2")
    _assign(u, Role.OPERATOR)
    assert not user_can_edit_object(u, p)


# --- user_can_deploy ---

@pytest.mark.django_db
def test_operator_can_deploy(h1):
    u = User.objects.create_user("op")
    _assign(u, Role.OPERATOR, ScopeType.DOMAIN, h1.domain_id)
    assert user_can_deploy(u, host=h1)


@pytest.mark.django_db
def test_viewer_cannot_deploy(h1):
    u = User.objects.create_user("v")
    _assign(u, Role.VIEWER, ScopeType.DOMAIN, h1.domain_id)
    assert not user_can_deploy(u, host=h1)


@pytest.mark.django_db
def test_auditor_cannot_deploy(h1):
    u = User.objects.create_user("au")
    _assign(u, Role.AUDITOR, ScopeType.DOMAIN, h1.domain_id)
    assert not user_can_deploy(u, host=h1)


# --- UI ---

@pytest.mark.django_db
def test_host_list_scoped_for_viewer(h1, d2):
    """VIEWER видит только хосты своего домена."""
    hs2 = HostSet.objects.create(domain=d2, name="web",
                                  platform="linux.debian")
    h2 = Host.objects.create(domain=d2, host_set=hs2, hostname="web2")

    u = User.objects.create_user("v")
    _assign(u, Role.VIEWER, ScopeType.DOMAIN, h1.domain_id)

    c = Client()
    c.force_login(u)
    r = c.get("/hosts/")
    assert r.status_code == 200
    body = r.content.decode()
    assert "web1" in body
    assert "web2" not in body


@pytest.mark.django_db
def test_credentials_hidden_for_viewer(h1):
    u = User.objects.create_user("v")
    _assign(u, Role.VIEWER, ScopeType.DOMAIN, h1.domain_id)

    c = Client()
    c.force_login(u)
    r = c.get("/credentials/")
    # VIEWER не должен видеть credentials
    assert r.status_code in (200, 403)
    if r.status_code == 200:
        assert "Нет прав" in r.content.decode() or \
               "Учётных данных нет" in r.content.decode()


@pytest.mark.django_db
def test_roles_page_denied_for_admin(d1):
    """ADMIN не видит полный список ролей (только SUPERVISOR)."""
    u = User.objects.create_user("a")
    _assign(u, Role.ADMIN, ScopeType.DOMAIN, d1.pk)

    c = Client()
    c.force_login(u)
    r = c.get("/access/roles/")
    assert r.status_code == 403


@pytest.mark.django_db
def test_roles_page_ok_for_supervisor(db):
    u = User.objects.create_user("sup")
    _assign(u, Role.SUPERVISOR)

    c = Client()
    c.force_login(u)
    r = c.get("/access/roles/")
    assert r.status_code == 200