from __future__ import annotations

import base64
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.core.models import TimeStampedModel


class SecretRef(TimeStampedModel):
    """Метаданные секрета.

    Само значение хранится:
      * в зашифрованном блобе (backend=local);
      * в KV v2 OpenBao (backend=openbao);
      * в .kdbx-файле (backend=keepass).

    SecretRef — это «паспорт» секрета: имя, где искать, кто владелец,
    когда последний раз использовался. Значения здесь нет и не будет.

    Owner nullable на время миграции (коммит 1.5 сделает его обязательным
    через backfill).
    """

    display_name = models.CharField(max_length=255, db_index=True)
    description = models.TextField(blank=True)

    backend = models.CharField(max_length=32, db_index=True)
    path = models.CharField(max_length=512, db_index=True)
    key = models.CharField(max_length=128, default="value")

    # --- scope: для UI-фильтров ---
    domain = models.ForeignKey(
        "inventory.Domain", null=True, blank=True,
        on_delete=models.CASCADE, related_name="secret_refs",
    )
    host_set = models.ForeignKey(
        "inventory.HostSet", null=True, blank=True,
        on_delete=models.CASCADE, related_name="secret_refs",
    )
    host = models.ForeignKey(
        "inventory.Host", null=True, blank=True,
        on_delete=models.CASCADE, related_name="secret_refs",
    )

    # --- ownership ---
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,          # станет обязательным в 1.5
        on_delete=models.PROTECT,
        related_name="owned_secrets",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    # --- учёт использования ---
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Ссылка на секрет"
        verbose_name_plural = "Ссылки на секреты"
        ordering = ["display_name"]
        unique_together = [("backend", "path", "key")]
        indexes = [
            models.Index(fields=["backend", "path"]),
            models.Index(fields=["owner", "backend"]),
            models.Index(fields=["-last_accessed_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.display_name} [{self.backend}:{self.path}:{self.key}]"

    def touch(self) -> None:
        from django.utils import timezone

        self.last_accessed_at = timezone.now()
        self.access_count = (self.access_count or 0) + 1
        self.save(update_fields=["last_accessed_at", "access_count"])

    def clean(self) -> None:
        if not self.path:
            raise ValidationError("path обязателен")
        if not self.backend:
            raise ValidationError("backend обязателен")
        if not self.key:
            raise ValidationError("key обязателен")


class SecretAccessGrant(TimeStampedModel):
    """Явный грант на чтение секрета другому пользователю.

    Даёт READ, не WRITE. Выдаёт только owner. Revoke — owner или SUPERVISOR.
    """

    ref = models.ForeignKey(
        SecretRef, on_delete=models.CASCADE, related_name="grants",
    )
    granted_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="secret_grants_received",
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="secret_grants_made",
    )
    reason = models.CharField(max_length=255, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    class Meta:
        verbose_name = "Грант на секрет"
        verbose_name_plural = "Гранты на секреты"
        unique_together = [("ref", "granted_to")]
        indexes = [
            models.Index(fields=["granted_to", "revoked_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.ref.display_name} → {self.granted_to}"

    @property
    def is_active(self) -> bool:
        from django.utils import timezone

        if self.revoked_at is not None:
            return False
        if self.valid_until and self.valid_until < timezone.now():
            return False
        return True


class SecretOwnershipTransfer(TimeStampedModel):
    """Передача владения секретом. Требует двухстороннего подтверждения."""

    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает подтверждения"
        EXECUTED = "executed", "Выполнено"
        CANCELLED = "cancelled", "Отменено"
        REJECTED = "rejected", "Отклонено"

    ref = models.ForeignKey(
        SecretRef, on_delete=models.CASCADE, related_name="ownership_transfers",
    )
    from_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="secret_transfers_out",
    )
    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="secret_transfers_in",
    )
    reason = models.CharField(max_length=255, blank=True)

    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="+",
    )
    approval_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.PENDING, db_index=True,
    )
    executed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Передача владения"
        verbose_name_plural = "Передачи владения"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.ref} : {self.from_user} → {self.to_user} [{self.status}]"
    

class ServerKey(TimeStampedModel):
    """Единственная запись. Зашифрованный блоб со всеми секретами.

    Salt и blob хранятся в base64. Мастер-ключ здесь не хранится никогда.
    Удаление записи = безвозвратная потеря всех секретов.
    """

    salt = models.CharField(max_length=64, help_text="base64 Argon2id salt")
    blob = models.TextField(help_text="base64 nonce + AES-GCM ciphertext")
    version = models.PositiveIntegerField(default=1)

    rotated_at = models.DateTimeField(null=True, blank=True)
    rotated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    class Meta:
        verbose_name = "Ключ сервера"
        verbose_name_plural = "Ключ сервера"

    def __str__(self) -> str:
        return f"ServerKey v{self.version} ({self.updated_at:%Y-%m-%d %H:%M})"

    @property
    def salt_bytes(self) -> bytes:
        return base64.b64decode(self.salt)

    @property
    def blob_bytes(self) -> bytes:
        return base64.b64decode(self.blob)

    @blob_bytes.setter
    def blob_bytes(self, value: bytes) -> None:
        self.blob = base64.b64encode(value).decode("ascii")


class SecretAccessLog(models.Model):
    """Аудит операций с секретами. Пишется даже в sealed-состоянии."""

    class Action(models.TextChoices):
        UNLOCK = "unlock", "Разблокировка"
        SEAL = "seal", "Блокировка"
        INIT = "init", "Инициализация"
        ROTATE = "rotate", "Смена мастер-ключа"
        RESET = "reset", "Сброс"
        READ = "read", "Чтение"
        WRITE = "write", "Запись"
        DELETE = "delete", "Удаление"
        BACKEND_CHANGE = "backend_change", "Смена backend"
        CREDENTIALS_CHANGE = "credentials_change", "Смена credentials"
        MIGRATE = "migrate", "Миграция"

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=32, choices=Action.choices)
    path = models.CharField(max_length=255, blank=True)
    key = models.CharField(max_length=128, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="secret_access_logs",
    )
    ip = models.GenericIPAddressField(null=True, blank=True)
    success = models.BooleanField(default=True)
    error = models.CharField(max_length=512, blank=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Журнал секретов"
        verbose_name_plural = "Журнал секретов"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "action"]),
            models.Index(fields=["-created_at", "success"]),
        ]

    def __str__(self) -> str:
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.action} {self.path}"


class SecretsMigration(TimeStampedModel):
    """История миграций секретов между backend'ами.

    Используется также как checkpoint: при прерывании сохраняется
    last_path/last_key, и `--resume <id>` продолжает с этого места.
    """

    class Status(models.TextChoices):
        RUNNING = "running", "Выполняется"
        SUCCESS = "success", "Успешно"
        PARTIAL = "partial", "Частично"
        FAILED = "failed", "Ошибка"
        CANCELLED = "cancelled", "Прервано"
        DRY_RUN = "dry_run", "Dry-run"

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False,
    )
    source_backend = models.CharField(max_length=32)
    target_backend = models.CharField(max_length=32)
    prefix = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.RUNNING, db_index=True,
    )

    total = models.PositiveIntegerField(default=0)
    done = models.PositiveIntegerField(default=0)
    skipped = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)

    overwrite = models.BooleanField(default=False)
    dry_run = models.BooleanField(default=False)
    activate_target = models.BooleanField(default=False)

    last_path = models.CharField(max_length=512, blank=True)
    last_key = models.CharField(max_length=128, blank=True)
    details = models.JSONField(
        default=list, blank=True,
        help_text="Последние N ошибок и пропусков",
    )

    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="secrets_migrations",
    )

    class Meta:
        verbose_name = "Миграция секретов"
        verbose_name_plural = "Миграции секретов"
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["-started_at", "status"]),
        ]

    def __str__(self) -> str:
        return (
            f"{self.source_backend} → {self.target_backend} "
            f"[{self.status}] {self.done}/{self.total}"
        )

    @property
    def progress_pct(self) -> int:
        if not self.total:
            return 100 if self.status != self.Status.RUNNING else 0
        processed = self.done + self.skipped + self.failed
        return min(100, int(round(processed * 100 / self.total)))

    @property
    def is_final(self) -> bool:
        return self.status in (
            self.Status.SUCCESS, self.Status.PARTIAL,
            self.Status.FAILED, self.Status.CANCELLED,
            self.Status.DRY_RUN,
        )

    def add_detail(self, kind: str, path: str, key: str, message: str = "") -> None:
        """Добавить запись в details, ограничивая размер (100 последних)."""
        self.details = list(self.details or [])
        self.details.append({
            "kind": kind, "path": path, "key": key, "message": message,
        })
        self.details = self.details[-100:]


def log_action(action, *, path="", key="", user=None, ip=None,
               success=True, error="", detail=None) -> None:
    try:
        SecretAccessLog.objects.create(
            action=action, path=path, key=key,
            user=user if user and getattr(user, "is_authenticated", False) else None,
            ip=ip, success=success, error=error[:512], detail=detail or {},
        )
    except Exception:
        from loguru import logger
        
        logger.exception("secrets: cannot write access log")

