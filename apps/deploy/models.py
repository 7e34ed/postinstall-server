from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from apps.core.models import TimeStampedModel, UUIDModel


class ServerIdentity(TimeStampedModel):
    """Ed25519 (подпись) и X25519 (шифрование) ключи сервера.

    Строго одна запись. Генерируется при первом обращении.

    TODO: перенести приватные ключи в secrets backend (OpenBao/KeePass),
    в БД держать только ссылки.
    """

    pubkey_ed25519 = models.TextField()
    privkey_ed25519 = models.TextField()
    pubkey_x25519 = models.TextField()
    privkey_x25519 = models.TextField()

    class Meta:
        verbose_name = "Ключи сервера"
        verbose_name_plural = "Ключи сервера"

    @classmethod
    def get_identity(cls) -> "ServerIdentity":
        obj = cls.objects.first()
        if obj:
            return obj
        from apps.deploy.services import generate_ed25519_keypair, generate_x25519_keypair

        ed_priv, ed_pub = generate_ed25519_keypair()
        x_priv, x_pub = generate_x25519_keypair()
        return cls.objects.create(
            pubkey_ed25519=ed_pub.decode(),
            privkey_ed25519=ed_priv.decode(),
            pubkey_x25519=x_pub.decode(),
            privkey_x25519=x_priv.decode(),
        )


class Agent(UUIDModel, TimeStampedModel):
    """Агент, привязанный к хосту."""

    agent_id = models.UUIDField(
        default=uuid.uuid4, unique=True, editable=False, db_index=True,
    )
    host = models.OneToOneField(
        "inventory.Host", on_delete=models.CASCADE, related_name="agent",
    )

    pubkey_ed25519 = models.TextField(help_text="Публичный ключ агента для подписи")
    pubkey_x25519 = models.TextField(help_text="Публичный ключ агента для шифрования")

    version = models.CharField(max_length=32, blank=True)

    is_active = models.BooleanField(default=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name = "Агент"
        verbose_name_plural = "Агенты"
        ordering = ["-last_seen_at"]

    def __str__(self) -> str:
        return f"{self.host.hostname} ({self.agent_id})"


class Deployment(UUIDModel, TimeStampedModel):
    """Задача на применение конфига к хосту."""

    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает"
        DISPATCHED = "dispatched", "Отправлена агенту"
        RUNNING = "running", "Выполняется"
        SUCCESS = "success", "Успешно"
        PARTIAL = "partial", "Частично"
        FAILED = "failed", "Ошибка"
        CANCELLED = "cancelled", "Отменена"
        EXPIRED = "expired", "Протухла"

    host = models.ForeignKey(
        "inventory.Host", on_delete=models.CASCADE, related_name="deployments",
    )
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True,
    )
    priority = models.SmallIntegerField(
        default=0, help_text="Больше — важнее",
    )
    rendered_config = models.JSONField(
        null=True, blank=True,
        help_text="Снапшот конфига, отправленного агенту",
    )

    dispatched_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="deployments_created",
    )
    bulk_deployment = models.ForeignKey(
        "BulkDeployment", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="deployments",
        verbose_name="Пакет",
    )

    class Meta:
        verbose_name = "Развёртывание"
        verbose_name_plural = "Развёртывания"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["host", "status"]),
            models.Index(fields=["status", "-priority", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.host.hostname} [{self.status}] {self.id}"


class DeploymentReport(TimeStampedModel):
    """Отчёт агента о применении."""

    deployment = models.OneToOneField(
        Deployment, on_delete=models.CASCADE, related_name="report",
    )

    status = models.CharField(max_length=16)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField()

    modules = models.JSONField(default=list)
    hardening = models.JSONField(default=list)

    agent_version = models.CharField(max_length=32, blank=True)
    error = models.TextField(blank=True)
    raw = models.JSONField(default=dict, help_text="Полный JSON от агента")

    class Meta:
        verbose_name = "Отчёт развёртывания"
        verbose_name_plural = "Отчёты развёртывания"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.deployment.host.hostname} [{self.status}]"


class BulkDeployment(UUIDModel, TimeStampedModel):
    """Батч из N задач, запущенных одной операцией."""

    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает"
        RUNNING = "running", "Выполняется"
        SUCCESS = "success", "Успешно"
        PARTIAL = "partial", "Частично"
        FAILED = "failed", "Ошибка"
        CANCELLED = "cancelled", "Отменён"

    name = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING,
        db_index=True,
    )

    total = models.PositiveIntegerField(default=0)
    succeeded = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)
    cancelled_count = models.PositiveIntegerField(default=0)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="bulk_deployments",
    )

    class Meta:
        verbose_name = "Пакет развёртываний"
        verbose_name_plural = "Пакеты развёртываний"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name or str(self.id)

    @property
    def pending(self) -> int:
        return max(0, self.total - self.succeeded - self.failed - self.cancelled_count)

    @property
    def progress_pct(self) -> int:
        if not self.total:
            return 0
        done = self.succeeded + self.failed + self.cancelled_count
        return int(round(done * 100 / self.total))

    @property
    def is_final(self) -> bool:
        return self.status in (
            self.Status.SUCCESS, self.Status.PARTIAL,
            self.Status.FAILED, self.Status.CANCELLED,
        )

    def recompute(self) -> None:
        """Пересчитать агрегаты по дочерним Deployment."""
        qs = self.deployments.all()
        total = qs.count()
        succeeded = qs.filter(status=Deployment.Status.SUCCESS).count()
        failed = qs.filter(status__in=[
            Deployment.Status.FAILED, Deployment.Status.EXPIRED,
        ]).count()
        cancelled = qs.filter(status=Deployment.Status.CANCELLED).count()

        self.total = total
        self.succeeded = succeeded
        self.failed = failed
        self.cancelled_count = cancelled

        finished = succeeded + failed + cancelled
        if self.status == self.Status.CANCELLED:
            pass
        elif finished < total:
            self.status = self.Status.RUNNING
        elif failed == 0 and cancelled == 0:
            self.status = self.Status.SUCCESS
        elif succeeded == 0 and cancelled == 0:
            self.status = self.Status.FAILED
        else:
            self.status = self.Status.PARTIAL

        self.save(update_fields=[
            "total", "succeeded", "failed", "cancelled_count", "status",
        ])