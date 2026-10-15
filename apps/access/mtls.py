"""mTLS: аутентификация через клиентские сертификаты.

Архитектура:

    Browser → [TLS + client cert] → Reverse proxy → [HTTP] → Django

Reverse proxy (nginx/traefik/haproxy) проверяет сертификат и передаёт
заголовки X-SSL-Client-*:

    X-SSL-Client-Verify:     SUCCESS | NONE | FAILED:...
    X-SSL-Client-Subject:    CN=ivan,OU=users,O=company
    X-SSL-Client-Fingerprint: <SHA256 hex, 64 символа>
    X-SSL-Client-Serial:     <serial hex>
    X-SSL-Client-Issuer:     CN=Company CA,O=company
    X-SSL-Client-NotBefore:  <ISO8601>
    X-SSL-Client-NotAfter:   <ISO8601>

Django принимает эти заголовки только от IP из AUTH_TRUSTED_PROXIES.
Если запрос не от прокси — заголовки игнорируются (защита от подделки
клиентом).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.http import HttpRequest
from loguru import logger

from apps.core.utils import get_client_ip

FP_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class MTLSError(Exception):
    pass


@dataclass
class ClientCert:
    fingerprint: str        # SHA256 hex, lowercase
    subject_dn: str
    issuer_dn: str
    serial: str
    not_before: datetime | None
    not_after: datetime | None
    verify_status: str      # "SUCCESS" | "NONE" | "FAILED:..."

    @property
    def is_verified(self) -> bool:
        return self.verify_status.upper() == "SUCCESS"


# def _client_ip(request: HttpRequest) -> str:
#     xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
#     if xff:
#         return xff.split(",")[0].strip()
#     return request.META.get("REMOTE_ADDR", "")


def _is_trusted_proxy(ip: str) -> bool:
    if not ip:
        return False
    trusted = getattr(settings, "AUTH_TRUSTED_PROXIES", []) or []
    if not trusted:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in trusted:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            logger.warning(f"mtls: некорректный CIDR: {cidr}")
    return False


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def extract_client_cert(request: HttpRequest) -> ClientCert | None:
    """Извлечь сертификат из заголовков reverse proxy.

    Возвращает None, если:
      * запрос пришёл не от доверенного proxy;
      * заголовков нет вовсе;
      * заголовки битые.
    """
    remote = request.META.get("REMOTE_ADDR", "")
    if not _is_trusted_proxy(remote):
        # Мы не доверяем заголовкам от НЕ-прокси. Но если proxy не настроен
        # (список пуст) — тоже не доверяем. Это безопасный дефолт.
        return None

    fp = request.META.get("HTTP_X_SSL_CLIENT_FINGERPRINT", "").strip().lower()
    verify = request.META.get("HTTP_X_SSL_CLIENT_VERIFY", "").strip()

    if not fp and not verify:
        # Сертификат не предъявлен — обычная ситуация при optional.
        return None

    if not fp or not FP_RE.match(fp):
        logger.warning(f"mtls: bad fingerprint from {remote}: {fp!r}")
        return None

    if not verify:
        # Заголовок Verify обязателен, если есть fingerprint
        logger.warning(f"mtls: fingerprint без verify от {remote}")
        return None

    return ClientCert(
        fingerprint=fp,
        subject_dn=request.META.get("HTTP_X_SSL_CLIENT_SUBJECT", "")[:512],
        issuer_dn=request.META.get("HTTP_X_SSL_CLIENT_ISSUER", "")[:512],
        serial=request.META.get("HTTP_X_SSL_CLIENT_SERIAL", "")[:128],
        not_before=_parse_iso(request.META.get(
            "HTTP_X_SSL_CLIENT_NOTBEFORE", "")),
        not_after=_parse_iso(request.META.get(
            "HTTP_X_SSL_CLIENT_NOTAFTER", "")),
        verify_status=verify,
    )


def find_certificate(cert: ClientCert):
    """Найти UserCertificate по отпечатку. None, если нет."""
    from .models import UserCertificate

    return UserCertificate.objects.filter(
        fingerprint_sha256=cert.fingerprint,
        is_active=True,
    ).select_related("user").first()


def is_certificate_valid(cert: ClientCert) -> tuple[bool, str]:
    """Проверка срока действия сертификата."""
    if not cert.is_verified:
        return False, f"verify_status={cert.verify_status}"

    now = datetime.now(tz=cert.not_after.tzinfo) if cert.not_after else None
    if now:
        if cert.not_before and now < cert.not_before:
            return False, "not yet valid"
        if cert.not_after and now > cert.not_after:
            return False, "expired"
    return True, "ok"


def mfa_enabled() -> bool:
    try:
        from constance import config

        return bool(config.AUTH_MTLS_ENABLED)
    except Exception:
        return bool(getattr(settings, "AUTH_MTLS_ENABLED", False))


def auto_login_enabled() -> bool:
    try:
        from constance import config

        return bool(config.AUTH_MTLS_AUTO_LOGIN)
    except Exception:
        return False


def allow_self_enroll() -> bool:
    try:
        from constance import config
        
        return bool(config.AUTH_MTLS_ALLOW_SELF_ENROLL)
    except Exception:
        return True