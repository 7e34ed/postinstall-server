from apps.core.ratelimit import RateLimitResult


def rate_limit_auditor(request, key_prefix, result: RateLimitResult, window: int):
    from apps.core.utils import get_client_ip

    from .models import AuthAuditLog, log_auth_event

    user = getattr(request, "user", None)
    ip = get_client_ip(request) or "unknown"

    log_auth_event(
        AuthAuditLog.Event.RATE_LIMITED,
        user=user if user and user.is_authenticated else None,
        ip=ip, success=False,
        detail={
            "action": key_prefix,
            "limit": result.limit,
            "window": window,
            "reset_in": result.reset_in,
            "current": result.current,
        }
    )