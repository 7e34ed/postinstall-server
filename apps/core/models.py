import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from .audit_chain import ChainedLogModel


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class AuditLog(models.Model):
    """HTTP-аудит. Append-only + hash chain."""

    ADVISORY_LOCK_KEY = 0x4155_4449_5431   # "AUDIT1" в hex, произвольно

    class Level(models.TextChoices):
        DEBUG = "debug", "DEBUG"
        INFO = "info", "INFO"
        WARNING = "warning", "WARNING"
        ERROR = "error", "ERROR"

    id = models.BigAutoField(primary_key=True)
    # created_at без auto_now_add — устанавливается в __init__,
    # иначе он попадёт в hash до сохранения
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    
    level = models.CharField(max_length=10, choices=Level.choices, default=Level.INFO)
    logger = models.CharField(max_length=64, blank=True)
    message = models.TextField()
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="audit_logs",
    )
    ip = models.GenericIPAddressField(null=True, blank=True)
    path = models.CharField(max_length=512, blank=True)
    method = models.CharField(max_length=10, blank=True)
    status_code = models.PositiveIntegerField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    payload = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "level"]),
            models.Index(fields=["user", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.level}: {self.message[:80]}"

    def _chain_payload(self) -> dict:
        return {
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "level": self.level,
            "logger": self.logger,
            "message": self.message,
            "user_id": self.user_id,
            "ip": self.ip,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "payload": self.payload,
        }
