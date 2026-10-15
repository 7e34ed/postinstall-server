from __future__ import annotations

from celery import shared_task
from django.contrib.auth import get_user_model
from django.utils import timezone
from loguru import logger

from apps.inventory.models import Host

from .models import BulkDeployment
from .services import (
    bulk_create_deployments,
    compute_config_hash,
    update_host_state,
)


@shared_task(name="apps.deploy.tasks.scan_drift")
def scan_drift_task(domain_id: int | None = None) -> dict:
    """Проходит по управляемым хостам и обновляет drift-состояние."""
    qs = Host.objects.filter(managed=True)
    if domain_id:
        qs = qs.filter(domain_id=domain_id)

    total = qs.count()
    drifted = 0
    unsynced = 0
    clean = 0

    for host in qs.iterator():
        try:
            result = update_host_state(host)
        except Exception:
            logger.exception(f"scan_drift: failed for {host.hostname}")
            continue

        if result["state"] == "drift":
            drifted += 1
        elif result["state"] == "unsynced":
            unsynced += 1
        else:
            clean += 1

    logger.info(
        f"scan_drift: total={total} clean={clean} "
        f"drift={drifted} unsynced={unsynced}"
    )
    return {
        "total": total, "clean": clean,
        "drifted": drifted, "unsynced": unsynced,
    }


@shared_task(name="apps.deploy.tasks.autodeploy_drifted")
def autodeploy_drifted_task(
    domain_id: int | None = None, user_id: int | None = None,
) -> dict:
    """Автоматически деплоит все хосты с обнаруженным дрифтом."""
    qs = Host.objects.filter(managed=True, drift_detected_at__isnull=False)
    if domain_id:
        qs = qs.filter(domain_id=domain_id)

    host_ids = list(qs.values_list("id", flat=True))
    if not host_ids:
        return {"bulk_id": None, "created": 0}

    user = None
    if user_id:
        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            pass

    result = bulk_create_deployments(
        host_ids, user=user,
        name=f"Автодеплой {timezone.now():%Y-%m-%d %H:%M}",
    )
    logger.info(
        f"autodeploy: bulk={result['bulk'].id} created={len(result['created'])} "
        f"skipped={len(result['skipped'])}"
    )
    return {
        "bulk_id": str(result["bulk"].id),
        "created": len(result["created"]),
        "skipped": len(result["skipped"]),
    }