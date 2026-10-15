import pytest
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, override_settings

from apps.access.models import (
    AuthAuditLog,
    RoleAssignment,
    UserCertificate,
)
from apps.access.mtls import (
    ClientCert,
    extract_client_cert,
    find_certificate,
    is_certificate_valid,
)
from apps.access.roles import Role

User = get_user_model()


FP_ALICE = "aa" * 32
FP_BOB = "bb" * 32


@pytest.fixture
def alice(db):
    u = User.objects.create_user("alice", password="pwd12345")
    return u


@pytest.fixture
def alice_cert(db, alice):
    return UserCertificate.objects.create(
        user=alice,
        label="Alice cert",
        fingerprint_sha256=FP_ALICE,
        subject_dn="CN=alice",
        is_active=True,
    )


# --- extract_client_cert ---

@override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"])
def test_extract_from_trusted_proxy():
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.1.2.3", **{
        "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
        "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
        "HTTP_X_SSL_CLIENT_SUBJECT": "CN=alice",
    })
    cert = extract_client_cert(r)
    assert cert is not None
    assert cert.fingerprint == FP_ALICE
    assert cert.is_verified


@override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"])
def test_extract_from_untrusted_proxy_ignored():
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="203.0.113.99", **{
        "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
        "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
    })
    assert extract_client_cert(r) is None


@override_settings(AUTH_TRUSTED_PROXIES=[])
def test_extract_no_trusted_proxies_returns_none():
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="127.0.0.1", **{
        "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
        "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
    })
    assert extract_client_cert(r) is None


@override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"])
def test_extract_bad_fingerprint():
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.1.2.3", **{
        "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
        "HTTP_X_SSL_CLIENT_FINGERPRINT": "not-hex",
    })
    assert extract_client_cert(r) is None


@override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"])
def test_extract_missing_verify():
    rf = RequestFactory()
    r = rf.get("/", REMOTE_ADDR="10.1.2.3", **{
        "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
    })
    assert extract_client_cert(r) is None


# --- find_certificate ---

@pytest.mark.django_db
def test_find_certificate(alice_cert):
    cert = ClientCert(
        fingerprint=FP_ALICE,
        subject_dn="", issuer_dn="", serial="",
        not_before=None, not_after=None,
        verify_status="SUCCESS",
    )
    uc = find_certificate(cert)
    assert uc is not None
    assert uc.user_id == alice_cert.user_id


@pytest.mark.django_db
def test_find_certificate_inactive(alice_cert):
    alice_cert.is_active = False
    alice_cert.save()
    cert = ClientCert(
        fingerprint=FP_ALICE,
        subject_dn="", issuer_dn="", serial="",
        not_before=None, not_after=None,
        verify_status="SUCCESS",
    )
    assert find_certificate(cert) is None


# --- is_certificate_valid ---

def test_certificate_valid_ok():
    from datetime import datetime, timedelta, timezone as tz

    cert = ClientCert(
        fingerprint=FP_ALICE,
        subject_dn="", issuer_dn="", serial="",
        not_before=datetime.now(tz.utc) - timedelta(days=1),
        not_after=datetime.now(tz.utc) + timedelta(days=365),
        verify_status="SUCCESS",
    )
    ok, _ = is_certificate_valid(cert)
    assert ok


def test_certificate_expired():
    from datetime import datetime, timedelta
    from datetime import timezone as tz

    cert = ClientCert(
        fingerprint=FP_ALICE,
        subject_dn="", issuer_dn="", serial="",
        not_before=datetime.now(tz.utc) - timedelta(days=365),
        not_after=datetime.now(tz.utc) - timedelta(days=1),
        verify_status="SUCCESS",
    )
    ok, reason = is_certificate_valid(cert)
    assert not ok
    assert reason == "expired"


def test_certificate_not_verified():
    cert = ClientCert(
        fingerprint=FP_ALICE,
        subject_dn="", issuer_dn="", serial="",
        not_before=None, not_after=None,
        verify_status="FAILED:certificate verify failed",
    )
    ok, reason = is_certificate_valid(cert)
    assert not ok
    assert "verify_status" in reason


# --- Middleware: интеграция ---

@pytest.mark.django_db
def test_auto_login_by_mtls(alice_cert):
    from constance import config

    config.AUTH_MTLS_ENABLED = True
    config.AUTH_MTLS_AUTO_LOGIN = True

    with override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"]):
        c = Client(REMOTE_ADDR="10.1.2.3")
        r = c.get("/hosts/", **{
            "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
            "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
            "HTTP_X_SSL_CLIENT_SUBJECT": "CN=alice",
        })
        # Пользователь залогинен автоматически
        assert r.wsgi_request.user.is_authenticated
        assert r.wsgi_request.user.username == "alice"


@pytest.mark.django_db
def test_no_auto_login_if_disabled(alice_cert):
    from constance import config

    config.AUTH_MTLS_ENABLED = True
    config.AUTH_MTLS_AUTO_LOGIN = False

    with override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"]):
        c = Client(REMOTE_ADDR="10.1.2.3")
        r = c.get("/hosts/", **{
            "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
            "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
        })
        assert not r.wsgi_request.user.is_authenticated


@pytest.mark.django_db
def test_aal3_set_on_mtls(alice_cert):
    from constance import config

    config.AUTH_MTLS_ENABLED = True
    config.AUTH_MTLS_AUTO_LOGIN = True

    with override_settings(AUTH_TRUSTED_PROXIES=["10.0.0.0/8"]):
        c = Client(REMOTE_ADDR="10.1.2.3")
        r = c.get("/hosts/", **{
            "HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS",
            "HTTP_X_SSL_CLIENT_FINGERPRINT": FP_ALICE,
        })
        assert c.session.get("psi_aal") == "aal3"


# --- UI ---

@pytest.mark.django_db
def test_certificates_list_requires_login(db):
    c = Client()
    r = c.get("/access/security/certificates/")
    assert r.status_code == 302


@pytest.mark.django_db
def test_certificates_list_ok(alice):
    c = Client()
    c.force_login(alice)
    r = c.get("/access/security/certificates/")
    assert r.status_code == 200


@pytest.mark.django_db
def test_enroll_certificate(alice):
    from constance import config
    
    config.AUTH_MTLS_ALLOW_SELF_ENROLL = True

    c = Client()
    c.force_login(alice)
    r = c.post("/access/security/certificates/", {
        "label": "My cert",
        "fingerprint": "cc" * 32,
        "subject_dn": "CN=alice",
    })
    assert r.status_code == 302
    assert UserCertificate.objects.filter(
        user=alice, fingerprint_sha256="cc" * 32,
    ).exists()


@pytest.mark.django_db
def test_enroll_duplicate_fingerprint(alice, alice_cert):
    c = Client()
    c.force_login(alice)
    r = c.post("/access/security/certificates/", {
        "label": "dup",
        "fingerprint": FP_ALICE,
    })
    assert r.status_code == 200
    assert "уже привязан" in r.content.decode()


@pytest.mark.django_db
def test_revoke_own_certificate(alice, alice_cert):
    c = Client()
    c.force_login(alice)
    r = c.post(
        f"/access/security/certificates/{alice_cert.pk}/revoke/",
        {"reason": "lost device"},
    )
    assert r.status_code == 302
    alice_cert.refresh_from_db()
    assert not alice_cert.is_active


@pytest.mark.django_db
def test_revoke_other_certificate_forbidden(alice, alice_cert):
    bob = User.objects.create_user("bob", password="pwd12345")
    c = Client()
    c.force_login(bob)
    r = c.post(
        f"/access/security/certificates/{alice_cert.pk}/revoke/",
        {"reason": "malicious"},
    )
    assert r.status_code == 403
    alice_cert.refresh_from_db()
    assert alice_cert.is_active