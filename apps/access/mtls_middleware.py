"""Middleware mTLS: автологин и обновление AAL."""
from __future__ import annotations

from django.contrib.auth import login as auth_login
from loguru import logger

from .mtls import (
    auto_login_enabled,
    extract_client_cert,
    find_certificate,
    is_certificate_valid,
    mfa_enabled,
)

# Пути, где middleware не вмешивается
MTLS_EXEMPT_PREFIXES = (
    "/static/",
    "/media/",
    "/favicon",
    "/api/v1/agent/",
    "/access/invite/",   # enroll до логина
    "/access/setup/",    # bootstrap
    "/accounts/",
)


class MTLSAuthenticationMiddleware:
    """Читает client cert из заголовков proxy.

    Логика:
      * если сертификата нет или он не от доверенного proxy — ничего;
      * если сертификат есть и пользователь уже залогинен — поднимаем
        сессионный AAL до AAL3 (hardware);
      * если сертификат есть и пользователь НЕ залогинен —
        при AUTH_MTLS_AUTO_LOGIN делаем login; иначе игнорируем
        (пусть логинится паролем);
      * если сертификат невалидный или не найден — логируем, не падаем.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not mfa_enabled():
            return self.get_response(request)

        path = request.path
        if any(path.startswith(p) for p in MTLS_EXEMPT_PREFIXES):
            return self.get_response(request)

        cert = extract_client_cert(request)
        if cert is None:
            return self.get_response(request)

        valid, reason = is_certificate_valid(cert)
        if not valid:
            logger.warning(
                f"mtls: cert rejected ({reason}), "
                f"subject={cert.subject_dn!r}"
            )
            return self.get_response(request)

        uc = find_certificate(cert)
        if uc is None:
            logger.info(
                f"mtls: unknown fingerprint {cert.fingerprint[:16]}… "
                f"(subject={cert.subject_dn!r})"
            )
            # Возможно, попытка enroll — обработается отдельно view'хой
            return self.get_response(request)

        user = uc.user
        if not user.is_active:
            logger.warning(f"mtls: user {user.username} inactive")
            return self.get_response(request)

        # --- Уже залогинен? ---
        if getattr(request, "user", None) and request.user.is_authenticated:
            if request.user.pk == user.pk:
                # Тот же — можно поднять AAL до AAL3
                self._upgrade_aal(request)
            else:
                # Другой пользователь — не трогаем сессию
                logger.warning(
                    f"mtls: cert for {user.username}, "
                    f"session for {request.user.username} — mismatch"
                )
            return self.get_response(request)

        # --- Автологин ---
        if not auto_login_enabled():
            return self.get_response(request)

        try:
            auth_login(
                request, user,
                backend="django.contrib.auth.backends.ModelBackend",
            )
            logger.info(
                f"mtls: auto-login {user.username} "
                f"(fp={cert.fingerprint[:16]}…)"
            )
            self._upgrade_aal(request)
            self._audit(request, user, cert)
        except Exception:
            logger.exception("mtls: auto-login failed")

        return self.get_response(request)

    @staticmethod
    def _upgrade_aal(request) -> None:
        from .aal import AAL
        from .session_aal import current_aal, set_aal

        if current_aal(request) < AAL.AAL3:
            set_aal(request, AAL.AAL3)

    @staticmethod
    def _audit(request, user, cert) -> None:
        from apps.core.utils import get_client_ip, get_user_agent

        from .models import AuthAuditLog, log_auth_event

        log_auth_event(
            AuthAuditLog.Event.LOGIN_SUCCESS,
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            detail={
                "method": "mtls",
                "fingerprint": cert.fingerprint,
                "subject": cert.subject_dn[:128],
            },
        )