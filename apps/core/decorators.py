"""Декораторы для rate-limit и прочего."""
from __future__ import annotations

from functools import wraps

from django.http import HttpResponse
from django.template.loader import render_to_string

from apps.core.utils import get_client_ip

from .ratelimit import hit


def rate_limit(*, limit: int, window: int, key_prefix: str = "action"):
    """Ограничение на действие.

    Ключ = key_prefix:user_id:ip.
    """
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            user = getattr(request, "user", None)
            uid = user.pk if user and user.is_authenticated else 0
            ip = get_client_ip(request) or "unknown"
            key = f"{key_prefix}:{uid}:{ip}"
            result = hit(key, limit=limit, window=window)
            if not result.allowed:
                from apps.access.models import AuthAuditLog, log_auth_event
                log_auth_event(
                    AuthAuditLog.Event.RATE_LIMITED,
                    user=user if user and user.is_authenticated else None,
                    ip=ip, success=False,
                    detail={
                        "action": key_prefix,
                        "limit": limit, "window": window,
                    },
                )
                html = render_to_string("access/rate_limited.html", {
                    "reset_in": result.reset_in,
                }, request=request)
                return HttpResponse(html, status=429, content_type="text/html")
            return view(request, *args, **kwargs)
        return wrapper
    return decorator