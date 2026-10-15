import pytest
from django.test import RequestFactory, override_settings

from apps.secrets.transport_guard import (
    InsecureTransport, enforce_secure_unseal, inspect_transport,
    is_secure_for_unseal,
)


@pytest.fixture
def rf():
    return RequestFactory()


def _https_request(rf, *, tls="TLSv1.3", remote="10.10.10.10"):
    r = rf.post("/admin/secrets/unlock/", {"master_key": "x"},
                secure=True, REMOTE_ADDR=remote)
    r.META["wsgi.url_scheme"] = "https"
    return r


# --- Прямое соединение ---

@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_MIN_TLS_VERSION="1.2",
    SECRETS_TRUSTED_PROXIES=[],
)
def test_http_rejected(rf):
    r = rf.post("/admin/secrets/unlock/", {"master_key": "x"})
    r.META["wsgi.url_scheme"] = "http"
    ok, reason, info = is_secure_for_unseal(r)
    assert not ok
    assert "scheme" in reason
    assert info.scheme == "http"


@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_MIN_TLS_VERSION="1.2",
    SECRETS_TRUSTED_PROXIES=[],
)
def test_https_no_tls_version_rejected(rf):
    # Django RequestFactory с secure=True, но без gunicorn.socket
    r = _https_request(rf)
    ok, reason, info = is_secure_for_unseal(r)
    # scheme=https, но версию TLS не определить → отказ
    assert not ok
    assert reason == "tls_version_unknown"


@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_TRUSTED_PROXIES=[],
)
def test_insecure_allowed_by_config(rf):
    with override_settings(SECRETS_ALLOW_INSECURE_UNSEAL=True):
        r = rf.post("/admin/secrets/unlock/", {"master_key": "x"})
        r.META["wsgi.url_scheme"] = "http"
        ok, reason, _ = is_secure_for_unseal(r)
        assert ok
        assert reason == "insecure_allowed_by_config"


# --- Через доверенный прокси ---

@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_MIN_TLS_VERSION="1.2",
    SECRETS_TRUSTED_PROXIES=["10.0.0.0/8"],
)
def test_proxy_https_tls13_ok(rf):
    r = rf.post(
        "/admin/secrets/unlock/", {"master_key": "x"},
        REMOTE_ADDR="10.1.2.3",
        HTTP_X_FORWARDED_PROTO="https",
        HTTP_X_FORWARDED_TLS_VERSION="TLSv1.3",
        HTTP_X_FORWARDED_FOR="203.0.113.5",
    )
    ok, reason, info = is_secure_for_unseal(r)
    assert ok
    assert info.source == "proxy"
    assert info.trusted_proxy
    assert info.tls_numeric == 4
    assert info.client_ip == "203.0.113.5"


@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_TRUSTED_PROXIES=["10.0.0.0/8"],
)
def test_proxy_http_rejected(rf):
    r = rf.post(
        "/admin/secrets/unlock/", {"master_key": "x"},
        REMOTE_ADDR="10.1.2.3",
        HTTP_X_FORWARDED_PROTO="http",
    )
    ok, reason, _ = is_secure_for_unseal(r)
    assert not ok


@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_MIN_TLS_VERSION="1.3",
    SECRETS_TRUSTED_PROXIES=["10.0.0.0/8"],
)
def test_proxy_tls12_below_min_13(rf):
    r = rf.post(
        "/admin/secrets/unlock/", {"master_key": "x"},
        REMOTE_ADDR="10.1.2.3",
        HTTP_X_FORWARDED_PROTO="https",
        HTTP_X_FORWARDED_TLS_VERSION="TLSv1.2",
    )
    ok, reason, info = is_secure_for_unseal(r)
    assert not ok
    assert "below_min" in reason
    assert info.tls_numeric == 3


# --- Заголовкам не доверяем без trusted proxy ---

@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_TRUSTED_PROXIES=[],
)
def test_untrusted_proxy_headers_ignored(rf):
    # Заголовки пришли, но REMOTE_ADDR не в списке → игнорируем
    r = rf.post(
        "/admin/secrets/unlock/", {"master_key": "x"},
        REMOTE_ADDR="203.0.113.99",
        HTTP_X_FORWARDED_PROTO="https",
        HTTP_X_FORWARDED_TLS_VERSION="TLSv1.3",
    )
    r.META["wsgi.url_scheme"] = "http"
    ok, reason, info = is_secure_for_unseal(r)
    assert not ok
    assert not info.trusted_proxy
    assert info.scheme == "http"


# --- Нормализация TLS-строк ---

@pytest.mark.parametrize("raw,expect_numeric", [
    ("TLSv1.2", 3),
    ("TLSv1.3", 4),
    ("TLS1.3", 4),
    ("1.3", 4),
    ("tlsv1.2", 3),
    ("TLS_1_3", 4),
    ("garbage", 0),
    ("", 0),
])
def test_tls_normalization(rf, raw, expect_numeric):
    with override_settings(
        SECRETS_TRUSTED_PROXIES=["0.0.0.0/0"],
        SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
        SECRETS_ALLOW_INSECURE_UNSEAL=False,
    ):
        r = rf.post(
            "/admin/secrets/unlock/", {"master_key": "x"},
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_FORWARDED_PROTO="https",
            HTTP_X_FORWARDED_TLS_VERSION=raw,
        )
        info = inspect_transport(r)
        assert info.tls_numeric == expect_numeric


# --- enforce_secure_unseal ---

@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_TRUSTED_PROXIES=[],
)
def test_enforce_raises_on_http(rf):
    r = rf.post("/admin/secrets/unlock/", {"master_key": "x"})
    r.META["wsgi.url_scheme"] = "http"
    with pytest.raises(InsecureTransport):
        enforce_secure_unseal(r)


# --- Настройка заголовка ---

@override_settings(
    SECRETS_REQUIRE_TLS_FOR_UNSEAL=True,
    SECRETS_ALLOW_INSECURE_UNSEAL=False,
    SECRETS_TRUSTED_PROXIES=["10.0.0.0/8"],
    SECRETS_TLS_VERSION_HEADER="HTTP_X_SSL_PROTOCOL",
)
def test_custom_tls_header(rf):
    r = rf.post(
        "/admin/secrets/unlock/", {"master_key": "x"},
        REMOTE_ADDR="10.1.2.3",
        HTTP_X_FORWARDED_PROTO="https",
        HTTP_X_SSL_PROTOCOL="TLSv1.3",
    )
    ok, _, info = is_secure_for_unseal(r)
    assert ok
    assert info.tls_numeric == 4