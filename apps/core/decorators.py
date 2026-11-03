"""Декораторы для rate-limit и прочего."""
from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.urls import reverse

from apps.core.utils import get_client_ip

from .aal import AAL
from .permissions import get_aal_requirement, get_user_roles
from .ratelimit import hit
from .session_aal import current_aal, is_aal_fresh

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


def _redirect_to_upgrade(request, target_aal: AAL):
    """Редирект на reauthenticate с возвратом на текущий путь."""
    url = reverse("mfa_reauthenticate")
    next_url = request.get_full_path()
    return redirect(f"{url}?next={next_url}&required={int(target_aal)}")


def require_aal(min_level: AAL):
    """Декоратор: требует минимальный AAL для view."""
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            user = getattr(request, "user", None)
            if not user or not user.is_authenticated:
                return redirect(
                    f"{reverse('account_login')}?next={request.get_full_path()}"
                )
            if user.is_superuser:
                return view(request, *args, **kwargs)

            level = current_aal(request)
            if level < min_level:
                from loguru import logger
                logger.info(
                    f"aal: {user.username} denied {request.path} "
                    f"(have={level.label}, need={min_level.label})"
                )
                return _redirect_to_upgrade(request, min_level)

            if not is_aal_fresh(request):
                from loguru import logger
                logger.info(f"aal: stale upgrade for {user.username}")
                return _redirect_to_upgrade(request, min_level)

            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def require_aal_action(action: str):
    """Требует AAL по имени действия (через провайдер access.aal)."""
    return require_aal(AAL(get_aal_requirement(action)))


def require_roles(*roles: str):
    """Требует хотя бы одну из ролей (через провайдер access.permissions)."""
    allowed = set(roles)

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            user = getattr(request, "user", None)
            if not user or not user.is_authenticated:
                return redirect(
                    f"{reverse('account_login')}?next={request.get_full_path()}"
                )
            if user.is_superuser:
                return view(request, *args, **kwargs)

            user_roles = get_user_roles(user)
            if not (user_roles & allowed):
                raise PermissionDenied(
                    f"Требуется одна из ролей: {sorted(allowed)}"
                )
            return view(request, *args, **kwargs)
        return wrapper
    return decorator