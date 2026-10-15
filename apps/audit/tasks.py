from __future__ import annotations

from celery import shared_task
from loguru import logger


@shared_task(name="apps.audit.tasks.seal_audit")
def seal_audit_task() -> dict:
    from .sealing import seal_all
    try:
        results = seal_all()
        return {
            "sealed": [
                {"source": r.source, "first": r.first_id,
                 "last": r.last_id, "count": r.count}
                for r in results
            ],
        }
    except Exception as exc:
        logger.exception("seal_audit failed")
        return {"error": str(exc)}


@shared_task(name="apps.audit.tasks.verify_audit")
def verify_audit_task(max_records: int = 10000) -> dict:
    from .sealing import verify_all
    try:
        results = verify_all(max_records=max_records)
        return {
            "results": [
                {"source": r.source, "status": r.status,
                 "broken_at": r.first_broken_id}
                for r in results
            ],
        }
    except Exception as exc:
        logger.exception("verify_audit failed")
        return {"error": str(exc)}


@shared_task(name="apps.audit.tasks.export_audit")
def export_audit_task() -> dict:
    from .export import export_to_file, export_to_syslog
    out: dict = {}
    try:
        out["file"] = export_to_file()
    except Exception as exc:
        logger.exception("export file failed")
        out["file_error"] = str(exc)
    try:
        out["syslog"] = export_to_syslog()
    except Exception as exc:
        logger.exception("export syslog failed")
        out["syslog_error"] = str(exc)
    return out