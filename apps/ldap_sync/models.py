from __future__ import annotations

from django.db import models

from apps.core.models import TimeStampedModel


class LDAPSyncRun(TimeStampedModel):
    """История запусков синка."""

    class Kind(models.TextChoices):
        HOSTS = "hosts", "Синхронизация компьютеров"
        USERS = "users", "Аугментация пользователей"
        VERIFY = "verify", "Проверка подключения"

    class Status(models.TextChoices):
        RUNNING = "running", "Выполняется"
        SUCCESS = "success", "Успешно"
        FAILED = "failed", "Ошибка"

    domain = models.ForeignKey(
        "inventory.Domain", on_delete=models.CASCADE,
        related_name="ldap_sync_runs",
        null=True, blank=True,
        help_text="Пусто для общих прогонов",
    )
    kind = models.CharField(max_length=16, choices=Kind.choices, db_index=True)
    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.RUNNING, db_index=True,
    )

    found = models.PositiveIntegerField(default=0)
    created = models.PositiveIntegerField(default=0)
    updated = models.PositiveIntegerField(default=0)
    skipped = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)

    error = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)

    started_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    triggered_by = models.ForeignKey(
        "auth.User", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    class Meta:
        verbose_name = "Прогон LDAP-синка"
        verbose_name_plural = "Прогоны LDAP-синка"
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"LDAP {self.kind} [{self.status}] {self.started_at:%Y-%m-%d %H:%M}"


class LDAPHostMap(TimeStampedModel):
    """Соответствие AD-компьютера и Host.

    Позволяет отслеживать, какие Host были созданы через синк.
    """

    domain = models.ForeignKey(
        "inventory.Domain", on_delete=models.CASCADE,
        related_name="ldap_host_maps",
    )
    ad_dn = models.CharField(max_length=512, unique=True)
    ad_sam = models.CharField(max_length=64, blank=True, db_index=True)
    ad_dns = models.CharField(max_length=255, blank=True)

    host = models.ForeignKey(
        "inventory.Host", on_delete=models.CASCADE,
        related_name="ldap_maps",
    )

    last_seen_in_ad = models.DateTimeField(null=True, blank=True)
    is_active_in_ad = models.BooleanField(default=True, db_index=True)

    class Meta:
        verbose_name = "LDAP: соответствие хост"
        verbose_name_plural = "LDAP: соответствия хостов"

    def __str__(self) -> str:
        return f"{self.ad_sam} → {self.host.hostname}"