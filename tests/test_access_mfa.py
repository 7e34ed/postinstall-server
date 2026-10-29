import pytest
from django.contrib.auth import get_user_model
from django.test import Client, override_settings
from django.utils import timezone

from apps.access.models import AuthAuditLog, RoleAssignment, UserActivity

User = get_user_model()


@pytest.fixture
def mfa_user(db):
    u = User.objects.create_user("mfa_user", password="password123")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.fixture
def no_mfa_user(db):
    u = User.objects.create_user("plain", password="password123")
    RoleAssignment.objects.create(
        user=u, role="viewer", scope_type="global", scope_id=0,
    )
    return u


@pytest.mark.django_db
def test_login_page_available(db):
    """Страница login отвечает 200 (интеграция allauth работает).

    Не проверяем HTML allauth-ui — это внешний контракт,
    который мы не контролируем. Проверяем только доступность
    и рендеринг нашего base.
    """
    c = Client()
    r = c.get("/accounts/login/")
    assert r.status_code == 200
    body = r.content.decode()
    # allauth-ui рендерится внутри нашего layout (daisyUI)
    assert "data-theme" in body or "csrfmiddlewaretoken" in body


@pytest.mark.django_db
def test_login_success(db, no_mfa_user):
    c = Client()
    r = c.post("/accounts/login/", {
        "login": "plain", "password": "password123",
    })
    assert r.status_code == 302
    log = AuthAuditLog.objects.filter(
        event=AuthAuditLog.Event.LOGIN_SUCCESS,
    ).last()
    assert log is not None
    assert log.user_id == no_mfa_user.pk


@pytest.mark.django_db
def test_login_failure_audited(db, no_mfa_user):
    c = Client()
    c.post("/accounts/login/", {"login": "plain", "password": "wrong"})
    log = AuthAuditLog.objects.filter(
        event=AuthAuditLog.Event.LOGIN_FAILED,
    ).last()
    assert log is not None
    assert not log.success


@pytest.mark.django_db
def test_mfa_index_accessible(db, mfa_user):
    c = Client()
    c.force_login(mfa_user)
    r = c.get("/accounts/2fa/")
    assert r.status_code == 200
    body = r.content.decode()
    # allauth-ui рендерится внутри нашего layout
    assert "data-theme" in body or "csrfmiddlewaretoken" in body


@pytest.mark.django_db
def test_mfa_enforcement_redirects_supervisor(db, mfa_user):
    from constance import config

    config.MFA_ENABLED = True
    config.MFA_REQUIRED_FOR_SUPERVISOR = True
    config.MFA_GRACE_PERIOD_HOURS = 0

    c = Client()
    c.force_login(mfa_user)
    r = c.get("/hosts/")
    assert r.status_code == 302
    assert "/accounts/2fa/totp/activate/" in r.url


@pytest.mark.django_db
def test_mfa_enforcement_skips_viewer(db, no_mfa_user):
    from constance import config

    config.MFA_ENABLED = True
    config.MFA_REQUIRED_FOR_SUPERVISOR = True

    c = Client()
    c.force_login(no_mfa_user)
    r = c.get("/hosts/")
    assert r.status_code in (200, 403)


@pytest.mark.django_db
def test_mfa_enforcement_grace_period(db, mfa_user):
    from constance import config
    
    config.MFA_ENABLED = True
    config.MFA_REQUIRED_FOR_SUPERVISOR = True
    config.MFA_GRACE_PERIOD_HOURS = 24

    UserActivity.objects.create(
        user=mfa_user, mfa_first_seen_at=timezone.now(),
    )

    c = Client()
    c.force_login(mfa_user)
    r = c.get("/hosts/")
    assert r.status_code in (200, 403)