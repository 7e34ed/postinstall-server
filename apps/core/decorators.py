"""Декораторы для rate-limit и прочего."""
from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from django.http import HttpResponse
from django.template.loader import render_to_string

from apps.core.utils import get_client_ip

from .ratelimit import hit

_rate_limit_auditor: Callable | None = None

def register_rate_limit_auditor(fn):
    global _rate_limit_auditor
    _rate_limit_auditor = fn


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
                try:
                    _rate_limit_auditor(request, key_prefix, result, window)
                except Exception:
                    from loguru import logger
                    logger.exception("core: rate_limit auditor failed")

                html = render_to_string("core/rate_limited.html", {
                    "reset_in": result.reset_in,
                }, request=request)
                return HttpResponse(html, status=429, content_type="text/html")
            return view(request, *args, **kwargs)
        return wrapper
    return decorator