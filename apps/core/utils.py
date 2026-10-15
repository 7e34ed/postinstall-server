"""Общие утилиты. Здесь только то, что реально используется
в нескольких приложениях.
"""
from __future__ import annotations

import copy


# ============================================================
#  HTTP
# ============================================================

def get_client_ip(request) -> str | None:
    """IP клиента с учётом X-Forwarded-For.

    Не учитывает доверенные прокси. Для операций, где это критично,
    см. apps.secrets.transport_guard.
    """
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def get_user_agent(request) -> str:
    """User-Agent, обрезанный до 512 символов."""
    if request is None:
        return ""
    return request.META.get("HTTP_USER_AGENT", "")[:512]


# ============================================================
#  Dict
# ============================================================

def deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивный merge. Возвращает новый dict, не мутирует base."""
    result = copy.deepcopy(base or {})
    for k, v in (override or {}).items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


# ============================================================
#  Scope
# ============================================================

def resolve_scope_object(scope_type: str, scope_id: int):
    """Объект scope по типу и id. None, если не найден.

    Импорты ленивые: чтобы core не тянул inventory на старте.
    """
    if scope_type == "global":
        return None
    try:
        if scope_type == "domain":
            from apps.inventory.models import Domain
            return Domain.objects.get(pk=scope_id)
        if scope_type == "host_set":
            from apps.inventory.models import HostSet
            return HostSet.objects.get(pk=scope_id)
        if scope_type == "host":
            from apps.inventory.models import Host
            return Host.objects.get(pk=scope_id)
    except Exception:
        return None
    return None