import pytest
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, override_settings
from django.utils import timezone

from apps.access.ip_allowlist import check_ip, is_ip_allowed
from apps.access.models import (
    AuthAuditLog,
    IPAllowlistRule,
    RoleAssignment,
    ServiceAccount,
    ServiceAccountToken,
)
from apps.access.service_auth import authenticate_request

User = get_user_model()


@pytest.fixture
def su(db):
    u = User.objects.create_user("su")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.fixture
def domain(db):
    from apps.inventory.models import Domain
    return Domain.objects.create(name="test.local")


# --- Service accounts ---

@pytest.mark.django_db
def test_service_account_token_issue(db, su, domain):
    acc = ServiceAccount.objects.create(
        name="ci-prod", scope=ServiceAccount.Scope.DEPLOY_DOMAIN,
        domain=domain, created_by=su,
    )
    token, plaintext = ServiceAccountToken.issue(account=acc)
    assert plaintext.startswith("sa_")
    assert token.token_prefix == plaintext[:12]


@pytest.mark.django_db
def test_service_token_verify_ok(db, su, domain):
    acc = ServiceAccount.objects.create(
        name="ci", scope=ServiceAccount.Scope.DEPLOY_DOMAIN,
        domain=domain, created_by=su,
    )
    _, plaintext = ServiceAccountToken.issue(account=acc)

    found = ServiceAccountToken.verify(plaintext)
    assert found is not None
    assert found.account_id == acc.pk


@pytest.mark.django_db
def test_service_token_verify_wrong(db, su, domain):
    acc = ServiceAccount.objects.create(
        name="ci2", scope=ServiceAccount.Scope.DEPLOY_DOMAIN,
        domain=domain, created_by=su,
    )
    ServiceAccountToken.issue(account=acc)
    assert ServiceAccountToken.verify("sa_wrong_token") is None


@pytest.mark.django_db
def test_service_token_expired(db, su, domain):
    acc = ServiceAccount.objects.create(
        name="ci3", scope=ServiceAccount.Scope.DEPLOY_DOMAIN,
        domain=domain, created_by=su,
    )
    token, plaintext = ServiceAccountToken.issue(
        account=acc, expires_at=timezone.now() - timezone.timedelta(hours=1),
    )
    assert ServiceAccountToken.verify(plaintext) is None


@pytest.mark.django_db
def test_service_token_revoked(db, su, domain):
    acc = ServiceAccount.objects.create(
        name="ci4", scope=ServiceAccount.Scope.DEPLOY_DOMAIN,
        domain=domain, created_by=su,
    )
    token, plaintext = ServiceAccountToken.issue(account=acc)
    token.revoked_at = timezone.now()
    token.save()
    assert ServiceAccountToken.verify(plaintext) is None


@pytest.mark.django_db
def test_authenticate_request_bearer(db, su, domain):
    acc = ServiceAccount.objects.create(
        name="ci5", scope=ServiceAccount.Scope.DEPLOY_DOMAIN,
        domain=domain, created_by=su,
    )
    _, plaintext = ServiceAccountToken.issue(account=acc)

    rf = RequestFactory()
    r = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    found = authenticate_request(r)
    assert found is not None
    assert found.pk == acc.pk


@pytest.mark.django_db
def test_service_account_clean_requires_domain(db):
    acc = ServiceAccount(name="x", scope=ServiceAccount.Scope.DEPLOY_DOMAIN)
    from django.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        acc.full_clean()


# --- IP allowlist ---

@pytest.mark.django_db
def test_ip_default_allow(db, su):
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.1.2.3")
    r.user = su
    ok, _ = check_ip(r, su)
    assert ok


@pytest.mark.django_db
def test_ip_user_rule_allow(db, su):
    IPAllowlistRule.objects.create(
        scope=IPAllowlistRule.Scope.USER,
        user=su, cidr="10.0.0.0/8",
    )
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.1.2.3")
    r.user = su
    ok, _ = check_ip(r, su)
    assert ok


@pytest.mark.django_db
def test_ip_user_rule_deny(db, su):
    IPAllowlistRule.objects.create(
        scope=IPAllowlistRule.Scope.USER,
        user=su, cidr="10.0.0.0/8",
    )
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="203.0.113.5")
    r.user = su
    ok, reason = check_ip(r, su)
    assert not ok
    assert "not in it" in reason


@pytest.mark.django_db
def test_ip_role_rule(db):
    u = User.objects.create_user("op")
    RoleAssignment.objects.create(
        user=u, role="operator", scope_type="global", scope_id=0,
    )
    IPAllowlistRule.objects.create(
        scope=IPAllowlistRule.Scope.ROLE,
        role="operator", cidr="192.168.0.0/16",
    )
    rf = RequestFactory()
    r_ok = rf.get("/", REMOTE_ADDR="192.168.1.5")
    assert check_ip(r_ok, u)[0]
    r_bad = rf.get("/", REMOTE_ADDR="10.0.0.5")
    assert not check_ip(r_bad, u)[0]


@pytest.mark.django_db
def test_ip_global_rule(db, su):
    IPAllowlistRule.objects.create(
        scope=IPAllowlistRule.Scope.GLOBAL,
        cidr="10.0.0.0/8",
    )
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.0.0.1")
    assert check_ip(r, su)[0]
    r2 = rf.get("/", REMOTE_ADDR="1.2.3.4")
    assert not check_ip(r2, su)[0]


@pytest.mark.django_db
def test_ip_superuser_exempt(db):
    u = User.objects.create_user("root", is_superuser=True)
    IPAllowlistRule.objects.create(
        scope=IPAllowlistRule.Scope.GLOBAL, cidr="10.0.0.0/8",
    )
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="8.8.8.8")
    assert check_ip(r, u)[0]


@pytest.mark.django_db
def test_is_ip_allowed_programmatic(db, su):
    IPAllowlistRule.objects.create(
        scope=IPAllowlistRule.Scope.USER,
        user=su, cidr="10.0.0.0/8",
    )
    assert is_ip_allowed("10.1.1.1", su)
    assert not is_ip_allowed("8.8.8.8", su)


# --- Rate limit ---

@pytest.mark.django_db
def test_rate_limit_allow(db):
    from apps.core.ratelimit import hit
    
    for _ in range(3):
        r = hit("test:key1", limit=3, window=60)
        assert r.allowed
    r = hit("test:key1", limit=3, window=60)
    assert not r.allowed


@pytest.mark.django_db
def test_rate_limit_reset_after_window(db):
    from django.core.cache import cache

    from apps.core.ratelimit import hit
    
    cache.clear()
    for _ in range(2):
        hit("test:key2", limit=2, window=60)
    cache.clear()
    r = hit("test:key2", limit=2, window=60)
    assert r.allowed


@pytest.mark.django_db
def test_rate_limit_decorator(db, su):
    from django.http import HttpResponse

    from apps.core.decorators import rate_limit

    @rate_limit(limit=1, window=60, key_prefix="test_act")
    def view(request):
        return HttpResponse("ok")

    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.0.0.1")
    r.user = su
    assert view(r).status_code == 200

    r2 = rf.get("/", REMOTE_ADDR="10.0.0.1")
    r2.user = su
    assert view(r2).status_code == 429