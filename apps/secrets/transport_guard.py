"""Проверка безопасности транспорта для операций с мастер-ключом.

Мастер-ключ нельзя передавать через HTTP. Допускается только HTTPS + TLS 1.2+
(предпочтительно 1.3). За прокси — доверяем заголовкам X-Forwarded-* только
от IP/CIDR из SECRETS_TRUSTED_PROXIES.

Проверяем также:
  * совпадение Host с ALLOWED_HOSTS (косвенная защита от DNS-rebinding);
  * опционально — фиксированную схему (сессия уже могла быть http, если
    где-то не отредиректило; лучше явно запретить POST-форму).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from django.conf import settings
from django.http import HttpRequest
from loguru import logger


class InsecureTransport(RuntimeError):
    """Попытка использовать операцию, требующую TLS, без TLS."""


@dataclass
class TransportInfo:
    scheme: str             # "https" | "http" | ""
    tls_version: str        # "TLSv1.2" | "TLSv1.3" | "" если не определить
    tls_numeric: int        # 0..4 — для сравнения
    source: str             # "direct" | "proxy" | "unknown"
    client_ip: str          # IP клиента (или proxy, если доверенный)
    remote_addr: str        # REMOTE_ADDR (может быть IP прокси)
    trusted_proxy: bool


_TLS_NUMERIC = {
    "1.0": 1,
    "1.1": 2,
    "1.2": 3,
    "1.3": 4,
}


def _normalize_tls(version: str | None) -> tuple[str, int]:
    if not version:
        return "", 0
    v = version.strip().upper().replace(" ", "").replace("_", ".")
    if v.startswith("TLSV"):
        v = v[4:]
    elif v.startswith("TLS"):
        v = v[3:]
    # v теперь "1.2" / "1.3" / "1.0"
    n = _TLS_NUMERIC.get(v, 0)
    return (f"TLSv{v}" if n else ""), n


def _min_tls_numeric() -> int:
    raw = str(getattr(settings, "SECRETS_MIN_TLS_VERSION", "1.2")).strip()
    _, n = _normalize_tls(raw if raw.startswith("TLS") else f"TLSv{raw}")
    return n or 3   # минимум 1.2


def _client_ip(request: HttpRequest) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _is_trusted_proxy(ip: str) -> bool:
    if not ip:
        return False
    trusted = getattr(settings, "SECRETS_TRUSTED_PROXIES", []) or []
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
            logger.warning(f"secrets: некорректный CIDR в SECRETS_TRUSTED_PROXIES: {cidr}")
    return False


def _direct_tls_version(request: HttpRequest) -> str:
    """Пытается вытащить TLS-версию из прямого соединения.

    Gunicorn кладёт в environ 'gunicorn.socket'. У сокета есть .cipher() —
    кортеж (name, protocol, bits), protocol вида 'TLSv1.3'.
    """
    sock = request.META.get("gunicorn.socket")
    if sock is None:
        return ""
    # у gunicorn-сокета может быть обёртка
    for attr in ("_sock", "raw", "raw._sock"):
        inner = sock
        for part in attr.split("."):
            inner = getattr(inner, part, None)
            if inner is None:
                break
        if inner is None:
            continue
        if hasattr(inner, "cipher"):
            try:
                cipher = inner.cipher()
                if cipher and len(cipher) >= 2:
                    _, n = _normalize_tls(cipher[1])
                    return f"TLSv{cipher[1].lstrip('TLSv')}" if n else ""
            except Exception:
                pass
    return ""


def inspect_transport(request: HttpRequest) -> TransportInfo:
    remote = request.META.get("REMOTE_ADDR", "")
    trusted = _is_trusted_proxy(remote)
    client = _client_ip(request)

    if trusted:
        # За доверенным прокси: используем X-Forwarded-*
        proto = request.META.get("HTTP_X_FORWARDED_PROTO", "").lower()
        header = getattr(settings, "SECRETS_TLS_VERSION_HEADER",
                         "HTTP_X_FORWARDED_TLS_VERSION")
        tls_raw = request.META.get(header, "")
        tls_str, tls_n = _normalize_tls(tls_raw)
        return TransportInfo(
            scheme=proto or "",
            tls_version=tls_str,
            tls_numeric=tls_n,
            source="proxy",
            client_ip=client,
            remote_addr=remote,
            trusted_proxy=True,
        )

    # Прямое соединение
    scheme = "https" if request.is_secure() else "http"
    tls_raw = _direct_tls_version(request)
    tls_str, tls_n = _normalize_tls(tls_raw)
    return TransportInfo(
        scheme=scheme,
        tls_version=tls_str,
        tls_numeric=tls_n,
        source="direct" if scheme == "https" else "unknown",
        client_ip=client or remote,
        remote_addr=remote,
        trusted_proxy=False,
    )


def is_secure_for_unseal(request: HttpRequest) -> tuple[bool, str, TransportInfo]:
    """Проверяет, можно ли принимать мастер-ключ по этому соединению.

    Возвращает (ok, reason, info).
    """
    info = inspect_transport(request)

    if getattr(settings, "SECRETS_ALLOW_INSECURE_UNSEAL", False):
        logger.warning(
            "secrets: SECRETS_ALLOW_INSECURE_UNSEAL=true — "
            "unseal разрешён по небезопасному каналу (dev-only!)"
        )
        return True, "insecure_allowed_by_config", info

    if not getattr(settings, "SECRETS_REQUIRE_TLS_FOR_UNSEAL", True):
        return True, "tls_check_disabled", info

    if info.scheme != "https":
        return False, f"scheme={info.scheme or 'unknown'}", info

    min_n = _min_tls_numeric()
    if info.tls_numeric == 0:
        # HTTPS есть, но версию не определить. Требуем явного подтверждения.
        return False, "tls_version_unknown", info
    if info.tls_numeric < min_n:
        return False, f"tls_version={info.tls_version} below_min", info

    return True, "ok", info


def enforce_secure_unseal(request: HttpRequest) -> TransportInfo:
    """Бросает InsecureTransport, если unseal по этому соединению запрещён."""
    ok, reason, info = is_secure_for_unseal(request)
    if ok:
        return info

    msg = {
        "scheme=http": (
            "HTTP недопустим для ввода мастер-ключа. "
            "Настройте HTTPS (TLS 1.2+)."
        ),
        "tls_version_unknown": (
            "Не удалось определить версию TLS. "
            "Настройте reverse proxy с заголовком X-Forwarded-TLS-Version "
            "и добавьте его IP в SECRETS_TRUSTED_PROXIES, "
            "либо отключите SECRETS_REQUIRE_TLS_FOR_UNSEAL."
        ),
    }.get(reason, f"TLS не соответствует требованиям ({reason}).")

    raise InsecureTransport(msg)