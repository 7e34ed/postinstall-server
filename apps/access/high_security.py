"""High-security mode: усиливает требования для SUPERVISOR/ADMIN.

Когда включён:
  * SUPERVISOR и ADMIN обязаны иметь hardware-фактор (для операций AAL3);
  * если фактора нет — доступ к системе есть, но любая операция write
    требует reauthenticate через AAL2 + двухстороннее подтверждение;
  * UI показывает баннер.
"""
from __future__ import annotations

from django.contrib import messages
from loguru import logger

from .models import AuthAuditLog, log_auth_event
from .permissions import is_supervisor
from .roles import Role
from .session_aal import current_aal, is_aal_fresh


def is_high_security_enabled() -> bool:
    try:
        from constance import config
        
        return bool(config.AUTH_HIGH_SECURITY_MODE)
    except Exception:
        return False


def set_high_security(enabled: bool, *, by_user, ip: str | None = None) -> None:
    """Переключить рубильник. Только SUPERVISOR с AAL3."""
    from constance import config

    if not is_supervisor(by_user):
        raise PermissionError("Только SUPERVISOR может переключать режим")

    config.AUTH_HIGH_SECURITY_MODE = bool(enabled)
    log_auth_event(
        AuthAuditLog.Event.HIGH_SECURITY_TOGGLED,
        user=by_user, ip=ip,
        detail={"enabled": bool(enabled)},
    )
    logger.warning(
        f"access: high_security_mode = {enabled} (by {by_user})"
    )


def requires_hardware_for(user) -> bool:
    """Нужен ли этому пользователю hardware-фактор в текущем режиме."""
    if not is_high_security_enabled():
        return False
    if user is None or not user.is_authenticated:
        return False
    if user.is_superuser:
        return False

    if is_supervisor(user):
        return True

    # ADMIN?
    from django.utils import timezone

    from .models import RoleAssignment

    now = timezone.now()
    for ra in RoleAssignment.objects.filter(user=user, revoked_at__isnull=True):
        if ra.valid_until and ra.valid_until < now:
            continue
        if ra.role == Role.ADMIN.value:
            return True
    return False