"""Проверка IP-allowlist.

Правило:
  1. superuser, break-glass-аккаунт, /api/v1/agent/* — пропускаем всегда.
  2. Если для пользователя есть USER-правила → IP должен быть среди них.
  3. Иначе, если для его ролей есть ROLE-правила → IP должен быть среди них.
  4. Иначе, если есть GLOBAL-правила → IP должен быть среди них.
  5. Иначе — доступ разрешён (default allow).
"""
from __future__ import annotations

import ipaddress

from django.http import HttpRequest
from loguru import logger

from apps.core.utils import get_client_ip

from .models import IPAllowlistRule

IP_ALLOWLIST_EXEMPT_PREFIXES = (
    "/static/",
    "/media/",
    "/favicon",
    "/api/v1/health",
    "/api/v1/agent/",       # у агентов свой слой
)


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            cidr, strict=False,
        )
    except ValueError:
        return False


def _is_exempt(request: HttpRequest, user) -> bool:
    if any(request.path.startswith(p) for p in IP_ALLOWLIST_EXEMPT_PREFIXES):
        return True
    if not user or not user.is_authenticated:
        return True   # анонимные запросы пропустим — логин сам по себе
                      # обрабатывается rate-limit'ом и allauth'ом
    if user.is_superuser:
        return True
    # break-glass
    try:
        from .models import BreakGlassAccount
        acc = BreakGlassAccount.get()
        if acc and acc.user_id == user.pk and acc.is_currently_active():
            return True
    except Exception:
        pass
    return False


def check_ip(request: HttpRequest, user) -> tuple[bool, str]:
    """Проверить IP.

    Возвращает (ok, reason).
    """
    if _is_exempt(request, user):
        return True, "exempt"

    ip = get_client_ip(request) or ""
    if not ip:
        return False, "cannot determine client IP"

    # 1) USER-правила
    user_rules = list(IPAllowlistRule.objects.filter(
        scope=IPAllowlistRule.Scope.USER,
        user=user, is_active=True,
    ))
    if user_rules:
        for r in user_rules:
            if _ip_in_cidr(ip, r.cidr):
                return True, f"user rule {r.cidr}"
        return False, f"user has allowlist, IP {ip} not in it"

    # 2) ROLE-правила
    from .permissions import active_roles
    
    role_names = {ra.role for ra in active_roles(user)}
    if role_names:
        role_rules = list(IPAllowlistRule.objects.filter(
            scope=IPAllowlistRule.Scope.ROLE,
            role__in=role_names, is_active=True,
        ))
        if role_rules:
            for r in role_rules:
                if _ip_in_cidr(ip, r.cidr):
                    return True, f"role rule {r.cidr}"
            return False, f"role has allowlist, IP {ip} not in it"

    # 3) GLOBAL-правила
    global_rules = list(IPAllowlistRule.objects.filter(
        scope=IPAllowlistRule.Scope.GLOBAL, is_active=True,
    ))
    if global_rules:
        for r in global_rules:
            if _ip_in_cidr(ip, r.cidr):
                return True, f"global rule {r.cidr}"
        return False, f"global allowlist, IP {ip} not in it"

    # 4) нет правил
    return True, "no rules"


def is_ip_allowed(ip: str, user) -> bool:
    """Программная проверка без request (для API, тестов)."""
    if user is None or not getattr(user, "is_authenticated", False):
        return True
    if user.is_superuser:
        return True

    from .permissions import active_roles

    user_rules = IPAllowlistRule.objects.filter(
        scope=IPAllowlistRule.Scope.USER,
        user=user, is_active=True,
    ).values_list("cidr", flat=True)
    if user_rules:
        return any(_ip_in_cidr(ip, c) for c in user_rules)

    role_names = {ra.role for ra in active_roles(user)}
    if role_names:
        role_rules = IPAllowlistRule.objects.filter(
            scope=IPAllowlistRule.Scope.ROLE,
            role__in=role_names, is_active=True,
        ).values_list("cidr", flat=True)
        if role_rules:
            return any(_ip_in_cidr(ip, c) for c in role_rules)

    global_rules = IPAllowlistRule.objects.filter(
        scope=IPAllowlistRule.Scope.GLOBAL, is_active=True,
    ).values_list("cidr", flat=True)
    if global_rules:
        return any(_ip_in_cidr(ip, c) for c in global_rules)

    return True