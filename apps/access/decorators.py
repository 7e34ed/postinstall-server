"""Декораторы проверки AAL и ролей."""
from __future__ import annotations

from functools import wraps

from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.urls import reverse
from loguru import logger

from .aal import AAL, requirement_for_path
from .session_aal import current_aal, is_aal_fresh


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
                logger.info(
                    f"aal: {user.username} denied {request.path} "
                    f"(have={level.label}, need={min_level.label})"
                )
                return _redirect_to_upgrade(request, min_level)

            if not is_aal_fresh(request):
                logger.info(f"aal: stale upgrade for {user.username}")
                return _redirect_to_upgrade(request, min_level)

            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def require_aal_path():
    """Декоратор: смотрит на AAL по URL, определённый в AAL_REQUIREMENTS."""
    
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            req = requirement_for_path(request.path)
            if req is None:
                return view(request, *args, **kwargs)
            return require_aal(req)(view)(request, *args, **kwargs)
        return wrapper
    return decorator


def require_aal_action(action: str):
    """Требует AAL по имени действия (из AAL_REQUIREMENTS_BY_ACTION)."""
    
    from .aal import requirement_for_action
    
    return require_aal(requirement_for_action(action))


def require_roles(*roles: str):
    """
    Требует хотя бы одну из ролей (без scope).

    Для view, где scope определяется внутри (например, профили).
    """
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

            from .permissions import active_roles
            user_roles = {ra.role for ra in active_roles(user)}
            if not (user_roles & allowed):
                raise PermissionDenied(
                    f"Требуется одна из ролей: {sorted(allowed)}"
                )
            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def require_permission(checker_name: str):
    """
    Требует, чтобы объектная проверка вернула True.

    checker_name — имя функции из permissions, например
    "user_can_edit_object". Объект берётся из kwargs view
    (обычно pk).
    """
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            user = getattr(request, "user", None)
            if not user or not user.is_authenticated:
                return redirect(
                    f"{reverse('account_login')}?next={request.get_full_path()}"
                )

            from . import permissions as perms

            checker = getattr(perms, checker_name)

            # Найти объект в kwargs — по ключам pk / pk_<name> / host_id
            obj = None
            for key in ("pk", "host_id", "host_set_id", "domain_id",
                        "profile_pk", "pk_host", "credential_pk"):
                if key in kwargs:
                    # Найти модель по значению через реестр
                    obj = _resolve_object_by_kwarg(request, key, kwargs[key])
                    if obj is not None:
                        break

            if obj is not None and not checker(user, obj):
                raise PermissionDenied(
                    f"Нет прав на операцию ({checker_name})"
                )

            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def _resolve_object_by_kwarg(request, key, value):
    """
    Грубый резолвер — ищет объект среди поддерживаемых моделей.

    В реальных view лучше использовать явный @require_permission
    с прямым obj = get_object_or_404(...). Здесь — для общих случаев.
    """
    from django.apps import apps

    mapping = {
        "pk": None,   # нельзя однозначно
        "host_id": "inventory.Host",
        "host_set_id": "inventory.HostSet",
        "domain_id": "inventory.Domain",
        "credential_pk": "credentials.Credential",
        "profile_pk": "config.ConfigProfile",
    }
    model_path = mapping.get(key)
    if not model_path:
        return None
    try:
        model = apps.get_model(model_path)
    except LookupError:
        return None
    try:
        return model.objects.get(pk=value)
    except model.DoesNotExist:
        return None