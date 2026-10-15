"""Экспорт аудита во внешнее хранилище (syslog, файл)."""
from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path
from typing import Any

from django.conf import settings
from django.utils import timezone
from loguru import logger

from .models import AuditExportCursor, AuditSeal
from .sources import get_source_model


def _syslog_handler(host: str, port: int, facility: str) -> logging.Handler:
    import logging.handlers as h

    fac = getattr(h.SysLogHandler, f"LOG_{facility.upper()}", h.SysLogHandler.LOG_LOCAL0)
    handler = h.SysLogHandler(address=(host, port), facility=fac)
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


def _record_to_dict(source: str, row) -> dict:
    if source == "audit_log":
        return {
            "source": source,
            "id": row.pk,
            "ts": row.created_at.isoformat(),
            "level": row.level,
            "logger": row.logger,
            "message": row.message,
            "user_id": row.user_id,
            "ip": row.ip,
            "path": row.path,
            "method": row.method,
            "status_code": row.status_code,
            "chain_hash": row.chain_hash,
        }
    return {
        "source": source,
        "id": row.pk,
        "ts": row.created_at.isoformat(),
        "event": row.event,
        "user_id": row.user_id,
        "target_user_id": row.target_user_id,
        "ip": row.ip,
        "success": row.success,
        "error": row.error,
        "chain_hash": row.chain_hash,
    }


def _get_or_create_cursor(source: str, target: str,
                           target_meta: dict) -> AuditExportCursor:
    obj, _ = AuditExportCursor.objects.get_or_create(
        source=source, target=target, target_meta=target_meta,
        defaults={"last_exported_id": 0},
    )
    return obj


def export_to_syslog(*, batch_size: int = 500) -> dict:
    """Выгрузить новые записи в syslog. Инкрементно, по курсору."""
    if not getattr(settings, "AUDIT_SYSLOG_ENABLED", False):
        return {"skipped": "disabled"}

    host = getattr(settings, "AUDIT_SYSLOG_HOST", "localhost")
    port = int(getattr(settings, "AUDIT_SYSLOG_PORT", 514))
    facility = getattr(settings, "AUDIT_SYSLOG_FACILITY", "local0")

    sl = logging.getLogger("postinstall.audit.syslog")
    sl.setLevel(logging.INFO)
    if not sl.handlers:
        sl.addHandler(_syslog_handler(host, port, facility))
    sl.propagate = False

    results = {}
    for source in AuditSeal.Source.values:
        Model = get_source_model(source)
        meta = {"host": host, "port": port, "facility": facility}
        cursor = _get_or_create_cursor(source, AuditExportCursor.Target.SYSLOG,
                                        meta)
        qs = Model.objects.filter(id__gt=cursor.last_exported_id).order_by("id")[:batch_size]
        n = 0
        last_id = cursor.last_exported_id
        for row in qs.iterator():
            payload = json.dumps(_record_to_dict(source, row), ensure_ascii=False)
            sl.info(payload)
            last_id = row.pk
            n += 1
        if n:
            cursor.last_exported_id = last_id
            cursor.last_exported_at = timezone.now()
            cursor.save(update_fields=["last_exported_id", "last_exported_at"])
        results[source] = n
    return results


def export_to_file(*, batch_size: int = 500,
                    path: Path | None = None) -> dict:
    """Выгрузить новые записи в файл (append-only).

    Файл размещается рядом с состоянием, ротация — внешняя (logrotate/s3).
    """
    base = Path(path or getattr(settings, "AUDIT_FILE_PATH",
                                 "/var/log/postinstall/audit-export.jsonl"))
    base.parent.mkdir(parents=True, exist_ok=True)

    results = {}
    for source in AuditSeal.Source.values:
        Model = get_source_model(source)
        cursor = _get_or_create_cursor(source, AuditExportCursor.Target.FILE,
                                        {"path": str(base)})
        qs = Model.objects.filter(id__gt=cursor.last_exported_id).order_by("id")[:batch_size]
        n = 0
        last_id = cursor.last_exported_id
        with base.open("a", encoding="utf-8") as f:
            for row in qs.iterator():
                f.write(json.dumps(_record_to_dict(source, row),
                                    ensure_ascii=False) + "\n")
                last_id = row.pk
                n += 1
        if n:
            cursor.last_exported_id = last_id
            cursor.last_exported_at = timezone.now()
            cursor.save(update_fields=["last_exported_id", "last_exported_at"])
        results[source] = n
    return results