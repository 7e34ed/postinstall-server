from __future__ import annotations

from celery import shared_task
from loguru import logger


@shared_task(name="apps.access.tasks.expire_stale_invitations")
def expire_stale_invitations_task() -> dict:
    from .services import expire_stale_invitations
    try:
        n = expire_stale_invitations()
        return {"expired": n}
    except Exception as exc:
        logger.exception("expire_stale_invitations: failed")
        return {"error": str(exc)}


@shared_task(name="apps.access.tasks.auto_disable_break_glass")
def auto_disable_break_glass_task() -> dict:
    from .services import auto_disable_expired_break_glass
    try:
        n = auto_disable_expired_break_glass()
        return {"disabled": n}
    except Exception as exc:
        logger.exception("auto_disable_break_glass failed")
        return {"error": str(exc)}


@shared_task(name="apps.access.tasks.start_access_review")
def start_access_review_task(user_id: int | None = None,
                              due_in_days: int = 14) -> dict:
    
    from django.contrib.auth import get_user_model

    from .services import start_access_review

    User = get_user_model()
    triggered_by = None
    if user_id:
        try:
            triggered_by = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            pass

    try:
        run = start_access_review(
            triggered_by=triggered_by, due_in_days=due_in_days,
            notes="Периодический access review (auto)",
        )
        return {"run_id": str(run.id), "total": run.total_assignments}
    except Exception as exc:
        logger.exception("start_access_review failed")
        return {"error": str(exc)}


@shared_task(name="apps.access.tasks.expire_overdue_review_items")
def expire_review_items_task() -> dict:
    from .services import expire_overdue_review_items
    try:
        n = expire_overdue_review_items()
        return {"expired": n}
    except Exception as exc:
        logger.exception("expire_review_items failed")
        return {"error": str(exc)}