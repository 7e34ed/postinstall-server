import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("DJANGO_CONFIGURATION", "Development")

# ВАЖНО: configurations.setup() нужно вызвать до обращения к django.conf.settings
import configurations  # type: ignore # noqa: E402

configurations.setup()

app = Celery("postinstall")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

# --- Периодические задачи ---

app.conf.beat_schedule = {
    "scan-drift": {
        "task": "apps.deploy.tasks.scan_drift",
        "schedule": 300.0,      # каждые 5 минут
    },
    "secrets-health": {
        "task": "apps.secrets.tasks.health_check",
        "schedule": 300.0,      # каждые 5 минут
    },
    "secrets-renew-openbao": {
        "task": "apps.secrets.tasks.renew_openbao_token",
        "schedule": 1800.0,     # каждые 30 минут
    },
    "expire-invitations": {
        "task": "apps.access.tasks.expire_stale_invitations",
        "schedule": 900.0,      # каждые 15 минут
    },
    "auto-disable-break-glass": {
        "task": "apps.access.tasks.auto_disable_break_glass",
        "schedule": 900.0,   # каждые 15 минут
    },
    "expire-review-items": {
        "task": "apps.access.tasks.expire_overdue_review_items",
        "schedule": 3600.0,  # каждый час
    },
    "quarterly-access-review": {
        "task": "apps.access.tasks.start_access_review",
        "schedule": 90 * 24 * 3600,   # раз в 90 дней
    },
    "audit-seal": {
        "task": "apps.audit.tasks.seal_audit",
        "schedule": 24 * 3600,     # раз в сутки
    },
    "audit-verify": {
        "task": "apps.audit.tasks.verify_audit",
        "schedule": 6 * 3600,      # раз в 6 часов
    },
    "audit-export": {
        "task": "apps.audit.tasks.export_audit",
        "schedule": 300.0,         # каждые 5 минут
    },
    "ldap-sync-all": {
        "task": "apps.ldap_sync.tasks.sync_all_domains",
        "schedule": 6 * 3600,   # каждые 6 часов
    },
}