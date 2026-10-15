from __future__ import annotations

from django.conf import settings
from django.db import models

from apps.core.models import TimeStampedModel

from .crypto import generate_ed25519_keypair


class AuditSigningKey(TimeStampedModel):
    """Ed25519-ключ для подписи seal'ов.

    Один ключ на инсталляцию. Если нужна ротация — старый сохраняется
    в истории, seal'ы ссылаются на свой ключ.
    """

    pubkey_pem = models.TextField()
    privkey_pem = models.TextField()
    is_active = models.BooleanField(default=True, db_index=True)
    description = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = "Ключ аудита"
        verbose_name_plural = "Ключи аудита"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"AuditKey [{self.created_at:%Y-%m-%d}] active={self.is_active}"

    @classmethod
    def get_active(cls) -> "AuditSigningKey":
        obj = cls.objects.filter(is_active=True).first()
        if obj:
            return obj
        priv, pub = generate_ed25519_keypair()
        return cls.objects.create(
            pubkey_pem=pub.decode(),
            privkey_pem=priv.decode(),
            description="Auto-generated",
        )


class AuditSeal(TimeStampedModel):
    """Запечатанный диапазон записей.

    Каждый seal фиксирует:
      * source          — какой лог (audit_log / auth_audit_log);
      * first_id/last_id — диапазон id записей;
      * count           — сколько записей;
      * chain_hash      — chain_hash последней записи диапазона;
      * signature       — Ed25519 от canonical payload.

    Верификация:
      1. Проверяем подпись seal'а.
      2. Проверяем, что chain_hash совпадает с полем последней записи.
      3. Проверяем непрерывность диапазонов (last_id + 1 = next.first_id).
    """

    class Source(models.TextChoices):
        AUDIT_LOG = "audit_log", "AuditLog"
        AUTH_AUDIT_LOG = "auth_audit_log", "AuthAuditLog"

    source = models.CharField(
        max_length=32, choices=Source.choices, db_index=True,
    )
    first_id = models.BigIntegerField()
    last_id = models.BigIntegerField(db_index=True)
    count = models.PositiveIntegerField()

    chain_hash = models.CharField(max_length=64)
    sealed_at = models.DateTimeField(auto_now_add=True, db_index=True)

    signature = models.TextField()
    key = models.ForeignKey(
        AuditSigningKey, on_delete=models.PROTECT, related_name="seals",
    )

    class Meta:
        verbose_name = "Seal аудита"
        verbose_name_plural = "Seal'ы аудита"
        ordering = ["-sealed_at"]
        unique_together = [("source", "last_id")]
        indexes = [
            models.Index(fields=["source", "-last_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.source} [{self.first_id}..{self.last_id}] ({self.count})"

    def canonical_payload(self) -> bytes:
        import json
        return json.dumps({
            "source": self.source,
            "first_id": self.first_id,
            "last_id": self.last_id,
            "count": self.count,
            "chain_hash": self.chain_hash,
        }, sort_keys=True, ensure_ascii=False).encode("utf-8")


class AuditExportCursor(TimeStampedModel):
    """Курсор экспорта в внешнее хранилище (syslog/файл).

    Один курсор на каждый target.
    """

    class Target(models.TextChoices):
        SYSLOG = "syslog", "Syslog"
        FILE = "file", "Файл"

    source = models.CharField(
        max_length=32, choices=AuditSeal.Source.choices, db_index=True,
    )
    target = models.CharField(max_length=16, choices=Target.choices, db_index=True)
    target_meta = models.JSONField(default=dict, blank=True,
                                    help_text="Путь к файлу, host:port и т.п.")

    last_exported_id = models.BigIntegerField(default=0)
    last_exported_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Курсор экспорта аудита"
        verbose_name_plural = "Курсоры экспорта аудита"
        unique_together = [("source", "target", "target_meta")]

    def __str__(self) -> str:
        return f"{self.source} → {self.target} (last_id={self.last_exported_id})"


class AuditVerifyRun(TimeStampedModel):
    """История запусков верификации."""

    class Status(models.TextChoices):
        OK = "ok", "OK"
        FAILED = "failed", "Ошибка"
        PARTIAL = "partial", "Частично"

    source = models.CharField(
        max_length=32, choices=AuditSeal.Source.choices, db_index=True,
    )
    status = models.CharField(max_length=16, choices=Status.choices)
    checked_records = models.BigIntegerField(default=0)
    checked_seals = models.PositiveIntegerField(default=0)
    first_broken_id = models.BigIntegerField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Прогон верификации"
        verbose_name_plural = "Прогоны верификации"
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.source} [{self.status}] {self.started_at:%Y-%m-%d %H:%M}"