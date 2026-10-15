from __future__ import annotations

from celery import shared_task
from loguru import logger

from .services import sync_hosts_for_domain


@shared_task(name="apps.ldap_sync.tasks.sync_hosts")
def sync_hosts_task(domain_id: int, run_id: str | None = None) -> dict:
    from apps.inventory.models import Domain

    from .models import LDAPSyncRun

    try:
        domain = Domain.objects.get(pk=domain_id)
    except Domain.DoesNotExist:
        return {"error": f"domain {domain_id} not found"}

    run = None
    if run_id:
        try:
            run = LDAPSyncRun.objects.get(pk=run_id)
        except LDAPSyncRun.DoesNotExist:
            run = None

    r = sync_hosts_for_domain(domain, run=run)
    return {
        "run_id": str(r.id),
        "status": r.status,
        "found": r.found,
        "created": r.created,
        "updated": r.updated,
        "failed": r.failed,
    }


@shared_task(name="apps.ldap_sync.tasks.sync_all_domains")
def sync_all_domains_task() -> dict:
    from apps.inventory.models import Domain
    results = {}
    for d in Domain.objects.filter(ldap_sync_enabled=True):
        try:
            r = sync_hosts_for_domain(d)
            results[d.name] = r.status
        except Exception as exc:
            logger.exception(f"sync_all: {d.name} failed")
            results[d.name] = f"error: {exc}"
    return results