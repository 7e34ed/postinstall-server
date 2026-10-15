from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apps.access.cert_parser import (
    ParsedCert,
    cert_matches_email,
    parse_cert_from_meta,
)


def _make_cert(*, cn: str, email: str | None = None,
                upn: str | None = None,
                san_email: str | None = None) -> str:
    """Сгенерировать тестовый сертификат. Возвращает PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if email:
        subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

    subject = x509.Name(subject_attrs)
    issuer = subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    )

    sans = []
    if san_email:
        sans.append(x509.RFC822Name(san_email))
    if upn:
        sans.append(x509.OtherName(
            type_id=x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
            value=upn.encode("utf-8"),
        ))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_parse_simple():
    pem = _make_cert(cn="ivan", san_email="ivan@company.local")
    meta = {"HTTP_X_SSL_CLIENT_CERT": quote(pem)}
    parsed = parse_cert_from_meta(meta)
    assert parsed is not None
    assert parsed.cn == "ivan"
    assert "ivan@company.local" in parsed.emails


def test_parse_upn():
    pem = _make_cert(cn="ivan", upn="ivan@company.local")
    meta = {"HTTP_X_SSL_CLIENT_CERT": quote(pem)}
    parsed = parse_cert_from_meta(meta)
    assert parsed is not None
    assert "ivan@company.local" in parsed.upns


def test_fallback_subject_header():
    meta = {
        "HTTP_X_SSL_CLIENT_SUBJECT": "CN=ivan,OU=users,DC=company,DC=local",
        "HTTP_X_SSL_CLIENT_FINGERPRINT": "aa" * 32,
    }
    parsed = parse_cert_from_meta(meta)
    assert parsed is not None
    assert parsed.cn == "ivan"
    assert parsed.fingerprint_sha256 == "aa" * 32


def test_match_san_email():
    pem = _make_cert(cn="ivan", san_email="ivan@company.local")
    parsed = parse_cert_from_meta({"HTTP_X_SSL_CLIENT_CERT": quote(pem)})
    ok, _ = cert_matches_email(parsed, "ivan@company.local")
    assert ok


def test_match_upn():
    pem = _make_cert(cn="ivan", upn="ivan@company.local")
    parsed = parse_cert_from_meta({"HTTP_X_SSL_CLIENT_CERT": quote(pem)})
    ok, _ = cert_matches_email(parsed, "ivan@company.local")
    assert ok


def test_match_fails():
    pem = _make_cert(cn="ivan", san_email="ivan@company.local")
    parsed = parse_cert_from_meta({"HTTP_X_SSL_CLIENT_CERT": quote(pem)})
    ok, reason = cert_matches_email(parsed, "petr@company.local")
    assert not ok
    assert "do not match" in reason


def test_match_no_identities():
    pem = _make_cert(cn="ivan")
    parsed = parse_cert_from_meta({"HTTP_X_SSL_CLIENT_CERT": quote(pem)})
    ok, reason = cert_matches_email(parsed, "ivan@company.local")
    assert not ok
    assert "no email" in reason