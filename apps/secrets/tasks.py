"""Celery-задачи для модуля secrets.

* renew_openbao_token — периодически обновляет токен OpenBao, если активный
  backend = openbao и токен renewable.
* health_check — кэширует health-статус активного backend, чтобы UI не
  дёргал OpenBao на каждый рендер.
"""
from __future__ import annotations

from celery import shared_task
from django.core.cache import cache
from loguru import logger

from .runtime import runtime

HEALTH_CACHE_KEY = "secrets:health:{name}"
HEALTH_TTL = 300
RENEW_THRESHOLD = 600   # если TTL < 10 минут — обновляем


def renew_openbao_token_now() -> dict:
    """Синхронный вызов renew (для UI и для celery).

    Возвращает dict: {"status": "ok"|"skipped"|"error", ...}
    """
    if not runtime.is_unsealed():
        return {"status": "skipped", "reason": "sealed"}

    try:
        active = runtime.get_active_backend()
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}

    if active != "openbao":
        return {"status": "skipped", "reason": f"active backend = {active}"}

    try:
        from .backends import get_backend
        backend = get_backend("openbao")
    except Exception as exc:
        logger.error(f"renew: backend init: {exc}")
        return {"status": "error", "detail": str(exc)}

    if not hasattr(backend, "maybe_renew_token"):
        return {"status": "skipped", "reason": "backend не поддерживает renew"}

    try:
        result = backend.maybe_renew_token()
    except Exception as exc:
        logger.exception("renew: unhandled error")
        return {"status": "error", "detail": str(exc)}

    if result is None:
        return {"status": "skipped", "reason": "renewable=False или TTL достаточен"}

    ttl = result.get("ttl")
    logger.info(f"renew: token renewed, new ttl={ttl}s")
    return {"status": "ok", "ttl": ttl}


@shared_task(name="apps.secrets.tasks.renew_openbao_token")
def renew_openbao_token() -> dict:
    """Периодическая задача. Логирует ошибки, не падает."""
    try:
        return renew_openbao_token_now()
    except Exception as exc:
        logger.exception("renew_openbao_token: unhandled")
        return {"status": "error", "detail": str(exc)}


@shared_task(name="apps.secrets.tasks.health_check")
def health_check(backend_name: str | None = None) -> dict:
    """Проверяет health активного backend и кэширует результат."""
    if not runtime.is_unsealed():
        cache.set(
            HEALTH_CACHE_KEY.format(name=backend_name or "*"),
            {"status": "sealed"},
            HEALTH_TTL,
        )
        return {"status": "skipped", "reason": "sealed"}

    from .services import get_active_backend, test_backend

    name = backend_name or get_active_backend()
    if not name:
        return {"status": "skipped", "reason": "no active backend"}

    try:
        result = test_backend(name)
    except Exception as exc:
        logger.exception(f"health_check({name}): unhandled")
        result = {"status": "error", "detail": str(exc)}

    cache.set(
        HEALTH_CACHE_KEY.format(name=name),
        result, HEALTH_TTL,
    )
    logger.debug(f"health_check: {name} → {result.get('status')}")
    return result