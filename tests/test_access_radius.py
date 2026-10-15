from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client, override_settings

from apps.access.auth_backends import (
    LocalOnlyBackend,
    RadiusBackend,
    _get_auth_source,
)
from apps.access.models import (
    AuthAuditLog,
    UserAuthSettings,
)

User = get_user_model()


@pytest.fixture
def radius_user(db):
    u = User.objects.create_user("alice", password="localpwd")
    UserAuthSettings.objects.create(
        user=u, auth_source=UserAuthSettings.Source.RADIUS,
    )
    return u


@pytest.fixture
def local_user(db):
    u = User.objects.create_user("bob", password="localpwd")
    # без UserAuthSettings — дефолт local
    return u


@pytest.fixture
def radius_enabled():
    from constance import config
    config.AUTH_RADIUS_ENABLED = True
    config.AUTH_RADIUS_HOST = "10.0.0.50"
    config.AUTH_RADIUS_SECRET = "shared-secret"
    config.AUTH_RADIUS_PORT = 1812
    config.AUTH_RADIUS_NAS_ID = "test"
    config.AUTH_RADIUS_TIMEOUT = 3
    config.AUTH_RADIUS_RETRIES = 2
    config.AUTH_RADIUS_FAIL_OPEN = False
    yield
    config.AUTH_RADIUS_ENABLED = False


def _make_radius_result(accepted=True, code=2, message=""):
    from apps.access.radius_client import RadiusResult
    return RadiusResult(accepted=accepted, code=code, message=message)


# --- Backend routing ---

@pytest.mark.django_db
def test_radius_backend_disabled(local_user):
    from constance import config
    config.AUTH_RADIUS_ENABLED = False

    backend = RadiusBackend()
    assert backend.authenticate(
        None, username="bob", password="localpwd",
    ) is None


@pytest.mark.django_db
def test_radius_backend_local_user_skipped(local_user, radius_enabled):
    backend = RadiusBackend()
    assert backend.authenticate(
        None, username="bob", password="any",
    ) is None


@pytest.mark.django_db
def test_radius_backend_success(radius_user, radius_enabled):
    backend = RadiusBackend()
    with patch("apps.access.auth_backends.authenticate") as mock_auth:
        mock_auth.return_value = _make_radius_result(accepted=True)
        user = backend.authenticate(
            None, username="alice", password="adpwd123456",
        )
        assert user == radius_user
        mock_auth.assert_called_once()


@pytest.mark.django_db
def test_radius_backend_reject(radius_user, radius_enabled):
    backend = RadiusBackend()
    with patch("apps.access.auth_backends.authenticate") as mock_auth:
        mock_auth.return_value = _make_radius_result(accepted=False, code=3)
        user = backend.authenticate(
            None, username="alice", password="wrong",
        )
        assert user is None


@pytest.mark.django_db
def test_radius_backend_timeout_fail_closed(radius_user, radius_enabled):
    from apps.access.radius_client import RadiusTimeout
    backend = RadiusBackend()
    with patch("apps.access.auth_backends.authenticate") as mock_auth:
        mock_auth.side_effect = RadiusTimeout("timeout")
        user = backend.authenticate(
            None, username="alice", password="adpwd123456",
        )
        assert user is None


@pytest.mark.django_db
def test_radius_backend_timeout_fail_open(radius_user, radius_enabled):
    from constance import config
    config.AUTH_RADIUS_FAIL_OPEN = True

    from apps.access.radius_client import RadiusTimeout
    backend = RadiusBackend()
    with patch("apps.access.auth_backends.authenticate") as mock_auth:
        mock_auth.side_effect = RadiusTimeout("timeout")
        user = backend.authenticate(
            None, username="alice", password="adpwd123456",
        )
        assert user is None   # всё равно None, но без отказа в логике


@pytest.mark.django_db
def test_radius_backend_inactive_user(radius_user, radius_enabled):
    radius_user.is_active = False
    radius_user.save()
    backend = RadiusBackend()
    assert backend.authenticate(
        None, username="alice", password="any",
    ) is None


@pytest.mark.django_db
def test_radius_backend_unknown_user(radius_enabled):
    backend = RadiusBackend()
    assert backend.authenticate(
        None, username="ghost", password="any",
    ) is None


# --- LocalOnlyBackend ---

@pytest.mark.django_db
def test_local_only_backend_allows_local_user(local_user):
    backend = LocalOnlyBackend()
    user = backend.authenticate(
        None, username="bob", password="localpwd",
    )
    assert user == local_user


@pytest.mark.django_db
def test_local_only_backend_blocks_radius_user(radius_user):
    backend = LocalOnlyBackend()
    # пароль в Django установлен, но auth_source=radius — блок
    user = backend.authenticate(
        None, username="alice", password="localpwd",
    )
    assert user is None


# --- get_auth_source ---

@pytest.mark.django_db
def test_get_auth_source_default(local_user):
    assert _get_auth_source(local_user) == "local"


@pytest.mark.django_db
def test_get_auth_source_radius(radius_user):
    assert _get_auth_source(radius_user) == "radius"


# --- UI ---

@pytest.mark.django_db
def test_radius_page_requires_supervisor(db):
    u = User.objects.create_user("plain")
    c = Client()
    c.force_login(u)
    r = c.get("/access/radius/")
    assert r.status_code == 403


@pytest.mark.django_db
def test_radius_page_supervisor_ok(db):
    from apps.access.models import RoleAssignment
    u = User.objects.create_user("sup")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    c = Client()
    c.force_login(u)
    r = c.get("/access/radius/")
    assert r.status_code == 200


@pytest.mark.django_db
def test_set_auth_source(db):
    from apps.access.models import RoleAssignment
    sup = User.objects.create_user("sup")
    RoleAssignment.objects.create(
        user=sup, role="supervisor", scope_type="global", scope_id=0,
    )
    target = User.objects.create_user("target")

    c = Client()
    c.force_login(sup)
    r = c.post(f"/access/users/{target.pk}/auth-source/",
               {"source": "radius"})
    assert r.status_code == 302
    s = UserAuthSettings.objects.get(user=target)
    assert s.auth_source == "radius"


# --- Полный флоу логина ---

@pytest.mark.django_db
def test_full_login_radius(radius_user, radius_enabled):
    c = Client()
    with patch("apps.access.auth_backends.authenticate") as mock_auth:
        mock_auth.return_value = _make_radius_result(accepted=True)
        r = c.post("/accounts/login/", {
            "login": "alice",
            "password": "adpwd123456",
        })
    assert r.status_code == 302
    assert c.session.get("psi_aal") == "aal2"

    log = AuthAuditLog.objects.filter(
        event=AuthAuditLog.Event.LOGIN_SUCCESS,
    ).last()
    assert log is not None
    assert log.detail.get("auth_source") == "radius"


@pytest.mark.django_db
def test_full_login_radius_reject(radius_user, radius_enabled):
    c = Client()
    with patch("apps.access.auth_backends.authenticate") as mock_auth:
        mock_auth.return_value = _make_radius_result(accepted=False, code=3)
        r = c.post("/accounts/login/", {
            "login": "alice",
            "password": "wrong",
        })
    # allauth при ошибке возвращает 200 (не redirect)
    assert r.status_code == 200
    assert not c.session.get("_auth_user_id")