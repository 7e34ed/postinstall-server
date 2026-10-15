import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from apps.access.aal import (
    AAL,
    aal3_strict,
    requirement_for_action,
    requirement_for_path,
)
from apps.access.models import RoleAssignment
from apps.access.roles import Role
from apps.access.session_aal import (
    current_aal,
    is_aal_fresh,
    reset_aal,
    set_aal,
)

User = get_user_model()


@pytest.fixture
def su(db):
    u = User.objects.create_user("su", password="pwd12345")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.fixture
def viewer(db):
    u = User.objects.create_user("viewer", password="pwd12345")
    RoleAssignment.objects.create(
        user=u, role="viewer", scope_type="global", scope_id=0,
    )
    return u


def test_requirement_for_path():
    assert requirement_for_path("/hosts/") == AAL.AAL1
    assert requirement_for_path("/admin/secrets/backend/") == AAL.AAL3
    assert requirement_for_path("/deploy/bulk/apply/") == AAL.AAL2
    assert requirement_for_path("/unknown/") is None


def test_requirement_prefers_longest_prefix():
    # /config/profiles/new/ (AAL2) длиннее чем /config/ (AAL1)
    assert requirement_for_path("/config/profiles/new/") == AAL.AAL2


def test_requirement_for_action():
    assert requirement_for_action("secrets.read") == AAL.AAL2
    assert requirement_for_action("secrets.rotate_master") == AAL.AAL3
    assert requirement_for_action("unknown") == AAL.AAL1


def test_aal_enum_comparison():
    assert AAL.AAL1 < AAL.AAL2 < AAL.AAL3
    assert AAL.AAL3 > AAL.AAL2 > AAL.AAL1
    assert AAL.NONE < AAL.AAL1


@pytest.mark.django_db
def test_current_aal_unauthenticated():
    from django.test import RequestFactory
    
    rf = RequestFactory()
    r = rf.get("/")
    r.user = None
    r.session = {}
    assert current_aal(r) == AAL.NONE


@pytest.mark.django_db
def test_current_aal_default_aal1(su):
    c = Client()
    c.force_login(su)
    r = c.get("/")
    # сессия установлена автоматически allauth, но сигнал сработал
    assert r.wsgi_request.session.get("psi_aal") in (None, "aal1")
    assert current_aal(r.wsgi_request) == AAL.AAL1


@pytest.mark.django_db
def test_set_aal(su):
    from django.test import RequestFactory

    rf = RequestFactory()
    r = rf.get("/")
    r.session = {}
    r.user = su

    set_aal(r, AAL.AAL2)
    assert r.session["psi_aal"] == "aal2"
    assert current_aal(r) == AAL.AAL2


@pytest.mark.django_db
def test_middleware_redirects_to_reauth(db, viewer):
    """VIEWER без TOTP идёт на /hosts/ (AAL1) без редиректа."""
    c = Client()
    c.force_login(viewer)
    r = c.get("/hosts/")
    # AAL1 достаточно, но нет прав/шаблонов — не важно, главное не 302 на reauth
    assert not (
        r.status_code == 302
        and "reauthenticate" in (r.get("Location") or "")
    )


@pytest.mark.django_db
def test_middleware_blocks_insufficient_aal(db, su):
    """SUPERVISOR с AAL1 при попытке AAL3-операции — редирект на reauth."""
    c = Client()
    c.force_login(su)
    # установим явно AAL1
    session = c.session
    session["psi_aal"] = "aal1"
    session.save()

    r = c.get("/admin/secrets/backend/")
    assert r.status_code == 302
    assert "reauthenticate" in (r.get("Location") or "")


@pytest.mark.django_db
def test_middleware_allows_superuser(db):
    """superuser всегда пропускается."""
    su = User.objects.create_user("root", password="pwd12345",
                                  is_superuser=True)
    c = Client()
    c.force_login(su)
    r = c.get("/admin/secrets/backend/")
    assert r.status_code in (200, 302, 403)
    # 302 — на /admin/, не на reauthenticate
    if r.status_code == 302:
        assert "reauthenticate" not in (r.get("Location") or "")


@pytest.mark.django_db
def test_high_security_toggle_requires_supervisor(db, viewer):
    from apps.access.high_security import set_high_security
    with pytest.raises(PermissionError):
        set_high_security(True, by_user=viewer)


@pytest.mark.django_db
def test_high_security_toggle_ok(db, su):
    from constance import config

    from apps.access.high_security import (
        is_high_security_enabled,
        set_high_security,
    )
    
    config.AUTH_HIGH_SECURITY_MODE = False

    set_high_security(True, by_user=su)
    assert is_high_security_enabled()


@pytest.mark.django_db
def test_aal3_strict_default_false(db):
    assert not aal3_strict()