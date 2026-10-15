"""Сигналы allauth и django.contrib.auth → AuthAuditLog."""
from __future__ import annotations

from allauth.account.signals import (
    user_logged_in as allauth_user_logged_in,
)
from allauth.account.signals import (
    user_logged_out as allauth_user_logged_out,
)
from allauth.account.signals import (
    user_login_failed,
)
from django.dispatch import receiver
from loguru import logger

from apps.access.auth_backends import _get_auth_source
from apps.core.utils import get_client_ip, get_user_agent

from .models import AuthAuditLog, log_auth_event


@receiver(allauth_user_logged_in)
def _log_login_success(sender, request, user, **kwargs):
    from .session_aal import set_aal
    from .aal import AAL

    # --- Break-glass: AAL3 + отдельный аудит ---
    is_break_glass = False
    try:
        from .models import BreakGlassAccount
        acc = BreakGlassAccount.get()
        if acc and acc.user_id == user.pk and acc.is_currently_active():
            is_break_glass = True
    except Exception:
        logger.exception("access: break-glass check failed")

    if is_break_glass:
        if request and hasattr(request, "session"):
            set_aal(request, AAL.AAL3)
        try:
            from .services import record_break_glass_use
            record_break_glass_use(user=user)
        except Exception:
            logger.exception("access: record break-glass use failed")

        log_auth_event(
            AuthAuditLog.Event.BREAK_GLASS_USED,
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            detail={"source": "password", "aal": "AAL3"},
        )
        logger.warning(
            f"access: BREAK-GLASS LOGIN by {user.username} "
            f"from {get_client_ip(request)}"
        )
        return

    # --- Обычный login ---
    try:
        from .radius_utils import get_auth_source
        source = get_auth_source(user)
        level = AAL.AAL2 if source == "radius" else AAL.AAL1
        if request and hasattr(request, "session"):
            set_aal(request, level)
    except Exception:
        logger.exception("access: cannot set AAL on login")

    log_auth_event(
        AuthAuditLog.Event.LOGIN_SUCCESS,
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        detail={"auth_source": _safe_auth_source(user)},
    )
    logger.info(f"access: login success {user.username}")


def _safe_auth_source(user) -> str:
    try:
        from .radius_utils import get_auth_source
        return get_auth_source(user)
    except Exception:
        return "local"


@receiver(allauth_user_logged_out)
def _log_logout(sender, request, user, **kwargs):
    if user is None or not getattr(user, "is_authenticated", False):
        return
    log_auth_event(
        AuthAuditLog.Event.LOGOUT,
        user=user, ip=get_client_ip(request), user_agent=get_user_agent(request),
    )


@receiver(user_login_failed)
def _log_login_failed(sender, credentials, request, **kwargs):
    username = (credentials or {}).get("login") or \
               (credentials or {}).get("username") or ""
    log_auth_event(
        AuthAuditLog.Event.LOGIN_FAILED,
        ip=get_client_ip(request), user_agent=get_user_agent(request),
        success=False,
        detail={"login": username},
    )


@receiver(allauth_user_logged_in)
def _log_login_success(sender, request, user, **kwargs):
    # AAL1 базово
    try:
        from .aal import AAL

        # Если пользователь radius — считаем AAL2 (RADIUS уже сделал
        # пароль+OTP в одном запросе)
        from .radius_utils import get_auth_source
        from .session_aal import set_aal
        
        # source = getattr(user, "auth_source", "local")
        source = get_auth_source(user)

        level = AAL.AAL2 if source == "radius" else AAL.AAL1
        if request and hasattr(request, "session"):
            set_aal(request, level)
    except Exception:
        logger.exception("access: cannot set AAL on login")

    log_auth_event(
        AuthAuditLog.Event.LOGIN_SUCCESS,
        user=user, ip=get_client_ip(request), user_agent=get_user_agent(request),
        detail={"auth_source": getattr(user, "auth_source", "local")},
    )
    logger.info(f"access: login success {user.username}")