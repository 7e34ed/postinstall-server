from datetime import datetime, timedelta

from django.utils import timezone
from loguru import logger

from .aal import AAL
from .permissions import user_max_aal  # провайдер

SESSION_KEY_AAL = "psi_aal"
SESSION_KEY_AAL_AT = "psi_aal_at"


def current_aal(request) -> AAL:
    if not request or not hasattr(request, "session"):
        return AAL.NONE
    if not request.user or not request.user.is_authenticated:
        return AAL.NONE

    raw = request.session.get(SESSION_KEY_AAL)
    level = AAL.from_str(raw) if raw else AAL.AAL1
    if level == AAL.NONE:
        level = AAL.AAL1

    max_level = AAL(user_max_aal(request.user))
    if level > max_level:
        level = max_level
    return level


# as is
def set_aal(request, level: AAL) -> None:
    if not request or not hasattr(request, "session"):
        return
    request.session[SESSION_KEY_AAL] = _to_str(level)
    request.session[SESSION_KEY_AAL_AT] = timezone.now().isoformat()
    logger.debug(f"aal: set {level.label}")


# as is
def reset_aal(request) -> None:
    if not request or not hasattr(request, "session"):
        return
    request.session.pop(SESSION_KEY_AAL, None)
    request.session.pop(SESSION_KEY_AAL_AT, None)


# as is
def current_aal_timestamp(request):
    if not request or not hasattr(request, "session"):
        return None
    ts = request.session.get(SESSION_KEY_AAL_AT)
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


# as is
def is_aal_fresh(request) -> bool:

    """Не истёк ли upgrade. Если сессия AAL1 — всегда fresh."""
    level = current_aal(request)
    if level == AAL.AAL1:
        return True
    ts = current_aal_timestamp(request)
    if ts is None:
        return False
    return (timezone.now() - ts) < _ttl()


# as is
def _ttl() -> timedelta:
    try:
        from constance import config
        
        seconds = int(config.AUTH_AAL_UPGRADE_TTL)
    except Exception:
        seconds = 900
    return timedelta(seconds=seconds)


# as is
def _to_str(level: AAL) -> str:
    return {
        AAL.AAL1: "aal1",
        AAL.AAL2: "aal2",
        AAL.AAL3: "aal3",
    }.get(level, "aal1")