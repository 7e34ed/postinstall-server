from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver
from loguru import logger

from .models import Deployment
from .services import update_host_hash_after_deployment


@receiver(post_save, sender=Deployment)
def _deployment_post_save(sender, instance: Deployment, created: bool, **kwargs):
    # 1) зафиксировать hash хоста при успехе
    if instance.status in (
        Deployment.Status.SUCCESS, Deployment.Status.PARTIAL,
    ):
        try:
            update_host_hash_after_deployment(instance)
        except Exception:
            logger.exception(
                f"deployment post_save: cannot update hash for "
                f"{instance.host.hostname}"
            )

    # 2) обновить агрегаты родительского батча
    if instance.bulk_deployment_id:
        try:
            instance.bulk_deployment.recompute()
        except Exception:
            logger.exception(
                f"deployment post_save: cannot recompute bulk "
                f"{instance.bulk_deployment_id}"
            )