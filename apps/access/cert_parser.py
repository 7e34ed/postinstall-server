"""Парсинг клиентского сертификата из заголовков reverse proxy.

nginx может передать полный PEM-сертификат через
`$ssl_client_escaped_cert` (URL-encoded). Это даёт нам доступ
к SAN, UPN и другим расширениям, которые не видны в Subject DN.

Мы не доверяем заголовку как источнику истины — middleware уже
проверил сертификат (verify_status=SUCCESS). Здесь мы только
извлекаем атрибуты для сопоставления с Invitation.email.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from loguru import logger

# OID UPN в AD (otherName)
UPN_OID = "1.3.6.1.4.1.311.20.2.3"

# OID для Kerberos principal name (реже)
KRB5_PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1"


@dataclass
class ParsedCert:
    """Извлечённые атрибуты сертификата."""
    subject_dn: str = ""
    issuer_dn: str = ""
    serial: str = ""
    fingerprint_sha256: str = ""
    not_before: str = ""
    not_after: str = ""

    cn: str = ""
    emails: list[str] = field(default_factory=list)
    upns: list[str] = field(default_factory=list)
    dns_names: list[str] = field(default_factory=list)

    @property
    def all_identities(self) -> set[str]:
        """Все возможные идентификаторы (lowercase) для сопоставления."""
        ids: set[str] = set()
        for e in self.emails:
            ids.add(e.lower().strip())
        for u in self.upns:
            ids.add(u.lower().strip())
        # CN иногда содержит email (редко, но бывает)
        if "@" in self.cn:
            ids.add(self.cn.lower().strip())
        return ids


def _decode_escaped_cert(raw: str) -> str | None:
    """nginx $ssl_client_escaped_cert URL-encoded. Декодируем."""
    if not raw:
        return None
    try:
        return unquote(raw)
    except Exception:
        return None


def _extract_san_emails(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ).value
    except x509.ExtensionNotFound:
        return []
    return [str(e.value).lower().strip()
            for e in san.get_values_for_type(x509.RFC822Name)]


def _extract_san_dns(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ).value
    except x509.ExtensionNotFound:
        return []
    return [str(e.value).lower().strip()
            for e in san.get_values_for_type(x509.DNSName)]


def _extract_san_upns(cert: x509.Certificate) -> list[str]:
    """UPN в AD хранится в SAN как otherName с OID 1.3.6.1.4.1.311.20.2.3."""
    result: list[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ).value
    except x509.ExtensionNotFound:
        return result

    try:
        for other in san.get_values_for_type(x509.OtherName):
            if other.type_id.dotted_string == UPN_OID:
                # Value в ASN.1 UTF8String — упрощённый парсинг
                value = _decode_othername_value(other.value)
                if value:
                    result.append(value.lower().strip())
    except Exception:
        pass
    return result


def _decode_othername_value(raw: bytes) -> str | None:
    """Простейший декодер ASN.1 UTF8String/PrintableString."""

    if not raw:
        return None
    # Наивно: ищем печатаемые ASCII после маркера строки
    try:
        text = raw.decode("utf-8", errors="ignore")
        # Убираем управляющие символы
        text = "".join(c for c in text if c.isprintable() or c == " ")
        text = text.strip()
        # Оставляем только часть, похожую на UPN
        m = re.search(r"[A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+", text)
        return m.group(0) if m else None
    except Exception:
        return None


def parse_cert_from_meta(meta: dict) -> ParsedCert | None:
    """Извлечь сертификат из request.META.

    Приоритет:
      1. HTTP_X_SSL_CLIENT_CERT (escaped) — полный PEM;
      2. fallback на отдельные заголовки (без SAN/UPN).

    Возвращает None, если сертификата нет или парсинг не удался.
    """
    raw_pem = meta.get("HTTP_X_SSL_CLIENT_CERT", "")
    if raw_pem:
        pem = _decode_escaped_cert(raw_pem)
        if pem:
            parsed = _parse_pem(pem)
            if parsed:
                return parsed
        logger.warning("cert_parser: не удалось разобрать PEM из заголовка")

    # Fallback: только subject DN, без SAN
    return _fallback_from_headers(meta)


def _parse_pem(pem: str) -> ParsedCert | None:
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except Exception as exc:
        logger.warning(f"cert_parser: PEM invalid: {exc}")
        return None

    cn = ""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
    except Exception:
        pass

    emails: list[str] = list(_extract_san_emails(cert))
    # Дополнительно — emailAddress в Subject DN (legacy OID)
    try:
        for attr in cert.subject.get_attributes_for_oid(
            NameOID.EMAIL_ADDRESS,
        ):
            emails.append(str(attr.value).lower().strip())
    except Exception:
        pass

    upns = _extract_san_upns(cert)
    dns_names = _extract_san_dns(cert)

    return ParsedCert(
        subject_dn=cert.subject.rfc4514_string(),
        issuer_dn=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        cn=str(cn),
        emails=list(set(emails)),
        upns=list(set(upns)),
        dns_names=list(set(dns_names)),
    )


def _fallback_from_headers(meta: dict) -> ParsedCert | None:
    """Если полного PEM нет — работаем с отдельными заголовками.

    Меньше информации (SAN/UPN недоступны), но лучше чем ничего.
    """

    subject = meta.get("HTTP_X_SSL_CLIENT_SUBJECT", "").strip()
    fp = meta.get("HTTP_X_SSL_CLIENT_FINGERPRINT", "").strip().lower()
    if not subject and not fp:
        return None

    # Парсим CN из subject DN
    cn = ""
    m = re.search(r"CN=([^,]+)", subject)
    if m:
        cn = m.group(1).strip()

    # Ищем email в subject DN
    emails: list[str] = []
    m = re.search(r"emailAddress=([^,]+)", subject)
    if m:
        emails.append(m.group(1).strip().lower())

    return ParsedCert(
        subject_dn=subject,
        fingerprint_sha256=fp,
        cn=cn,
        emails=emails,
    )


def cert_matches_email(cert: ParsedCert, email: str) -> tuple[bool, str]:
    """Совпадает ли сертификат с email.

    Возвращает (ok, reason).
    """
    target = (email or "").lower().strip()
    if not target:
        return False, "empty target email"

    ids = cert.all_identities
    if not ids:
        return False, "certificate has no email/UPN/SAN"

    if target in ids:
        return True, "exact match"

    return False, (
        f"certificate identities {sorted(ids)} do not match {target!r}"
    )