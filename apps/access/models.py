from __future__ import annotations

import hashlib
import secrets
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

from apps.core.models import TimeStampedModel

from .roles import DUAL_APPROVAL_ROLES, Role, ScopeType


class UserAuthSettings(TimeStampedModel):
    """Настройки аутентификации пользователя.

    Отдельная таблица, чтобы не патчить django.contrib.auth.User.
    """

    class Source(models.TextChoices):
        LOCAL = "local", "Локальная (Django)"
        RADIUS = "radius", "RADIUS / Aladdin HOTP"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="auth_settings",
    )
    auth_source = models.CharField(
        max_length=16, choices=Source.choices,
        default=Source.LOCAL, db_index=True,
    )
    radius_username = models.CharField(
        max_length=150, blank=True,
        help_text="Если отличается от Django-username",
    )

    class Meta:
        verbose_name = "Настройки аутентификации"
        verbose_name_plural = "Настройки аутентификации"

    def __str__(self) -> str:
        return f"{self.user} [{self.auth_source}]"


class SuperuserBootstrap(models.Model):  # noqa: DJ008
    """Singleton. Отслеживает setup-фазу и root-учётку."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1,
                                          editable=False)
    is_setup_complete = models.BooleanField(default=False, db_index=True)

    initial_superuser = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    setup_started_at = models.DateTimeField(auto_now_add=True)
    setup_completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Bootstrap"
        verbose_name_plural = "Bootstrap"

    def save(self, *args, **kwargs):
        self.id = 1
        super().save(*args, **kwargs)

    @classmethod
    def get(cls) -> "SuperuserBootstrap":
        obj, _ = cls.objects.get_or_create(id=1)
        return obj

    @classmethod
    def mark_setup_complete(cls, *, superuser) -> "SuperuserBootstrap":
        obj = cls.get()
        obj.is_setup_complete = True
        obj.setup_completed_at = timezone.now()
        if superuser is not None:
            obj.initial_superuser = superuser
        obj.save(update_fields=[
            "is_setup_complete", "setup_completed_at", "initial_superuser",
        ])
        return obj


class RoleAssignment(models.Model):
    """Одно назначение роли с областью действия.

    GLOBAL: scope_id = 0.
    Остальное: scope_id = pk соответствующей сущности.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="role_assignments",
    )
    role = models.CharField(max_length=32, db_index=True)
    scope_type = models.CharField(max_length=16, db_index=True)
    scope_id = models.PositiveBigIntegerField(default=0)

    valid_until = models.DateTimeField(null=True, blank=True)

    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="roles_granted",
    )
    granted_at = models.DateTimeField(auto_now_add=True)

    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="roles_revoked",
    )
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoke_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = "Назначение роли"
        verbose_name_plural = "Назначения ролей"
        ordering = ["-granted_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "role", "scope_type", "scope_id"],
                name="unique_active_role_assignment",
                condition=models.Q(revoked_at__isnull=True),
            ),
        ]
        indexes = [
            models.Index(fields=["user", "revoked_at"]),
            models.Index(fields=["role", "scope_type", "scope_id",
                                  "revoked_at"]),
        ]

    def __str__(self) -> str:
        scope = f"{self.scope_type}:{self.scope_id}" if self.scope_type != ScopeType.GLOBAL \
            else "global"
        return f"{self.user} [{self.role} @ {scope}]"

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.valid_until and self.valid_until < timezone.now():
            return False
        return True

    def clean(self) -> None:
        if self.scope_type == ScopeType.GLOBAL and self.scope_id != 0:
            raise ValidationError("scope_id должен быть 0 для GLOBAL")
        if self.scope_type != ScopeType.GLOBAL and self.scope_id == 0:
            raise ValidationError(
                f"scope_id обязателен для scope_type={self.scope_type}"
            )


class Invitation(models.Model):
    """Приглашение.

    Если role ∈ DUAL_APPROVAL_ROLES — обязательны две подписи
    (approval1 + approval2). Иначе одна (invited_by).
    """

    class Status(models.TextChoices):
        PENDING_APPROVAL = "pending_approval", "Ожидает подтверждения"
        PENDING = "pending", "Ожидает принятия"
        ACCEPTED = "accepted", "Принят"
        REVOKED = "revoked", "Отозван"
        REJECTED = "rejected", "Отклонён"
        EXPIRED = "expired", "Истёк"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(db_index=True)
    role = models.CharField(max_length=32)
    scope_type = models.CharField(max_length=16)
    scope_id = models.PositiveBigIntegerField(default=0)
    valid_until = models.DateTimeField(
        null=True, blank=True,
        help_text="Срок действия роли после accept",
    )

    token_hash = models.CharField(max_length=64, db_index=True, unique=True)
    expires_at = models.DateTimeField(db_index=True)

    status = models.CharField(
        max_length=32, choices=Status.choices,
        default=Status.PENDING_APPROVAL, db_index=True,
    )

    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="invitations_sent",
    )
    approval1_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="invitations_approval1",
    )
    approval1_at = models.DateTimeField(null=True, blank=True)
    approval2_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="invitations_approval2",
    )
    approval2_at = models.DateTimeField(null=True, blank=True)

    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="invitations_accepted",
    )
    accepted_at = models.DateTimeField(null=True, blank=True)

    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="invitations_revoked",
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    email_sent_at = models.DateTimeField(null=True, blank=True)
    email_send_error = models.CharField(max_length=512, blank=True)
    email_attempts = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Приглашение"
        verbose_name_plural = "Приглашения"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email", "status"]),
            models.Index(fields=["-created_at", "status"]),
        ]

    def __str__(self) -> str:
        return f"{self.email} → {self.role} [{self.status}]"

    @property
    def is_expired(self) -> bool:
        return self.expires_at < timezone.now()

    @property
    def approvals_count(self) -> int:
        return sum(1 for x in (self.approval1_by_id, self.approval2_by_id) if x)

    def required_approvals(self) -> int:
        return 2 if self.role in {r.value for r in _DUAL_APPROVAL} else 1


# Лениво, чтобы избежать циклического импорта
from .roles import DUAL_APPROVAL_ROLES as _DUAL_APPROVAL  # noqa: E402


class RoleChangeNotice(models.Model):
    """Алерт пользователю об изменении его ролей.

    Пока not acknowledged — middleware не пускает никуда, кроме самого
    экрана /access/roles-changed/ и logout.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="role_change_notices",
    )
    changes = models.JSONField(default=list)
    reason = models.TextField(blank=True)

    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        verbose_name = "Уведомление о смене ролей"
        verbose_name_plural = "Уведомления о смене ролей"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "acknowledged_at"]),
        ]


class DeputyAssignment(models.Model):
    """Заместитель SUPERVISOR'а.

    PEER     — уже SUPERVISOR, просто документируем «кого звать первым».
    ELEVATED — ADMIN, получает право подтверждать consensus-инвойсы,
               когда principal неактивен дольше activation_delay_hours.
    """

    class Kind(models.TextChoices):
        PEER = "peer", "Равный SUPERVISOR"
        ELEVATED = "elevated", "Повышаемый на время"

    principal = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="deputies",
    )
    deputy = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="is_deputy_for",
    )
    kind = models.CharField(max_length=16, choices=Kind.choices,
                             default=Kind.PEER)

    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    activation_delay_hours = models.PositiveIntegerField(default=24)

    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="deputies_created",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Заместитель"
        verbose_name_plural = "Заместители"
        unique_together = [("principal", "deputy")]
        ordering = ["principal"]

    def __str__(self) -> str:
        return f"{self.deputy} → за {self.principal} ({self.get_kind_display()})"

    def clean(self) -> None:
        if self.principal_id == self.deputy_id:
            raise ValidationError("principal и deputy не могут совпадать")

    def is_currently_elevated(self) -> bool:
        """Активен ли ELEVATED-режим прямо сейчас."""
        if self.kind != self.Kind.ELEVATED or not self.is_active:
            return False
        now = timezone.now()
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        # Если окно задано — считаем активным в окне.
        if self.valid_from or self.valid_until:
            return True
        # Иначе — только если principal молчит дольше activation_delay.
        try:
            act = self.principal.activity
            if act.last_activity_at is None:
                return True
            delta = timezone.now() - act.last_activity_at
            return delta.total_seconds() >= self.activation_delay_hours * 3600
        except UserActivity.DoesNotExist:
            return True


class UserActivity(models.Model):
    """Активность пользователя. Обновляется middleware, не чаще раза в минуту."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="activity",
    )
    last_activity_at = models.DateTimeField(null=True, blank=True, db_index=True)
    mfa_first_seen_at = models.DateTimeField(null=True, blank=True)


class UserCertificate(models.Model):
    """Клиентский сертификат (mTLS / Rutoken).

    Аутентификация через reverse proxy: nginx проверяет сертификат и
    передаёт X-SSL-Client-* заголовки. Мы мапим fingerprint на user.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="certificates",
    )
    label = models.CharField(max_length=128)
    subject_dn = models.CharField(max_length=512)
    fingerprint_sha256 = models.CharField(
        max_length=64, unique=True, db_index=True,
    )
    serial = models.CharField(max_length=128, blank=True)
    issuer_dn = models.CharField(max_length=512, blank=True)
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_to = models.DateTimeField(null=True, blank=True)

    is_active = models.BooleanField(default=True, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = "Клиентский сертификат"
        verbose_name_plural = "Клиентские сертификаты"
        ordering = ["user", "label"]

    def __str__(self) -> str:
        return f"{self.user} / {self.label}"


class AuthAuditLog(models.Model):
    """Журнал аутентификации и изменений доступа.

    Отдельно от AuditLog (HTTP) — этот про безопасность.
    
    Аудит аутентификации/авторизации. Append-only + hash chain
    """

    ADVISORY_LOCK_KEY = 0x4155_5448_4155   # "AUTHAU" в hex

    class Event(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Успешный вход"
        LOGIN_FAILED = "login_failed", "Неуспешный вход"
        LOGOUT = "logout", "Выход"
        MFA_ENROLLED = "mfa_enrolled", "MFA подключён"
        MFA_DISABLED = "mfa_disabled", "MFA отключён"
        MFA_SUCCESS = "mfa_success", "MFA успешно"
        MFA_FAILED = "mfa_failed", "MFA неуспешно"
        ROLE_GRANTED = "role_granted", "Роль выдана"
        ROLE_REVOKED = "role_revoked", "Роль отозвана"
        INVITE_CREATED = "invite_created", "Инвайт создан"
        INVITE_APPROVED = "invite_approved", "Инвайт подтверждён"
        INVITE_ACCEPTED = "invite_accepted", "Инвайт принят"
        INVITE_REVOKED = "invite_revoked", "Инвайт отозван"
        CERT_ADDED = "cert_added", "Сертификат добавлен"
        CERT_REVOKED = "cert_revoked", "Сертификат отозван"
        DEPUTY_ASSIGNED = "deputy_assigned", "Заместитель назначен"
        DEPUTY_USED = "deputy_used", "Заместитель использован"
        HIGH_SECURITY_TOGGLED = "high_security_toggled", "Переключён режим"
        SETUP_COMPLETED = "setup_completed", "Setup завершён"
        AUTH_SOURCE_CHANGED = "auth_source_changed", "Изменён источник аутентификации"
        BREAK_GLASS_ENABLED = "break_glass_enabled", "Break-glass включён"
        BREAK_GLASS_USED = "break_glass_used", "Break-glass использован"
        BREAK_GLASS_DISABLED = "break_glass_disabled", "Break-glass выключен"
        ACCESS_REVIEW_STARTED = "access_review_started", "Access review запущен"
        ACCESS_REVIEW_CONFIRMED = "access_review_confirmed", "Роль подтверждена"
        ACCESS_REVIEW_REVOKED = "access_review_revoked", "Роль отозвана по review"
        SERVICE_TOKEN_ISSUED = "service_token_issued", "Сервисный токен выдан"
        SERVICE_TOKEN_REVOKED = "service_token_revoked", "Сервисный токен отозван"
        IP_DENIED = "ip_denied", "Отказ по IP"
        RATE_LIMITED = "rate_limited", "Отказ по rate-limit"

    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    event = models.CharField(max_length=32, choices=Event.choices, db_index=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)

    detail = models.JSONField(default=dict, blank=True)
    success = models.BooleanField(default=True)
    error = models.CharField(max_length=512, blank=True)

    class Meta:
        verbose_name = "Аудит доступа"
        verbose_name_plural = "Аудит доступа"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "event"]),
            models.Index(fields=["user", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.event}"

    def _chain_payload(self) -> dict:
        return {
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "event": self.event,
            "user_id": self.user_id,
            "target_user_id": self.target_user_id,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "detail": self.detail,
            "success": self.success,
            "error": self.error,
        }

class DirectRoleAssignment(TimeStampedModel):
    """Прямое назначение роли существующему пользователю.

    Для ADMIN и AUDITOR — двухстороннее подтверждение (2 SUPERVISOR'а).
    Для OPERATOR и VIEWER — достаточно одной подписи.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает"
        EXECUTED = "executed", "Выполнено"
        REJECTED = "rejected", "Отклонено"
        CANCELLED = "cancelled", "Отменено"

    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="direct_assignments",
    )
    role = models.CharField(max_length=32)
    scope_type = models.CharField(max_length=16)
    scope_id = models.PositiveBigIntegerField(default=0)
    valid_until = models.DateTimeField(null=True, blank=True)

    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="direct_assignments_initiated",
    )
    approval1_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    approval1_at = models.DateTimeField(null=True, blank=True)
    approval2_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    approval2_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.PENDING, db_index=True,
    )
    reason = models.CharField(max_length=255, blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Прямое назначение роли"
        verbose_name_plural = "Прямые назначения ролей"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.target_user} ← {self.role} @ {self.scope_type}:{self.scope_id}"

    def required_approvals(self) -> int:
        return 2 if self.role in {r.value for r in DUAL_APPROVAL_ROLES} else 1


# --- Утилита аудита ---

def log_auth_event(event: str, *, user=None, target_user=None,
                   ip=None, user_agent="", detail=None,
                   success=True, error="") -> None:
    try:
        AuthAuditLog.objects.create(
            event=event,
            user=user if user and getattr(user, "is_authenticated", False) else None,
            target_user=target_user,
            ip=ip,
            user_agent=(user_agent or "")[:512],
            detail=detail or {},
            success=success,
            error=(error or "")[:512],
        )
    except Exception:
        from loguru import logger
        
        logger.exception("access: cannot write AuthAuditLog")


class BreakGlassAccount(TimeStampedModel):
    """Аварийный доступ.

    Единственная запись. Активируется вручную через management-команду
    или через UI SUPERVISOR'ом с AAL3. Включает break-glass-пользователя
    (username=break-glass) на ограниченное время.

    Когда активен:
      * позволяет войти с паролем из physical safe;
      * AAL повышается до AAL3 только для этого пользователя;
      * все действия пишутся в AuthAuditLog с флагом break_glass=true;
      * мгновенно уведомляются все SUPERVISOR'ы (email + audit).
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="break_glass_account",
    )

    is_enabled = models.BooleanField(default=False, db_index=True)

    enabled_at = models.DateTimeField(null=True, blank=True)
    enabled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    enabled_reason = models.CharField(max_length=255, blank=True)

    # Автоматическое выключение через N часов после включения
    auto_disable_after_hours = models.PositiveIntegerField(default=24)

    last_used_at = models.DateTimeField(null=True, blank=True)
    use_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Break-glass account"
        verbose_name_plural = "Break-glass accounts"

    def __str__(self) -> str:
        state = "enabled" if self.is_enabled else "disabled"
        return f"Break-glass [{state}]"

    @classmethod
    def get(cls) -> "BreakGlassAccount | None":
        return cls.objects.first()

    @classmethod
    def create_default(cls, *, user, password: str) -> "BreakGlassAccount":
        """Создать break-glass-учётку. Пароль генерируется случайно.

        Флаг is_active=False до явного включения через UI.
        """
        user.set_password(password)
        user.is_active = False
        user.save(update_fields=["password", "is_active"])
        return cls.objects.create(user=user)

    def is_currently_active(self) -> bool:
        if not self.is_enabled:
            return False
        if self.enabled_at is None:
            return False
        hours = self.auto_disable_after_hours or 24
        deadline = self.enabled_at + timezone.timedelta(hours=hours)
        return timezone.now() < deadline

    def enable(self, *, by_user, reason: str = "") -> None:
        self.is_enabled = True
        self.enabled_at = timezone.now()
        self.enabled_by = by_user
        self.enabled_reason = reason
        self.save(update_fields=[
            "is_enabled", "enabled_at", "enabled_by", "enabled_reason",
        ])
        self.user.is_active = True
        self.user.save(update_fields=["is_active"])

    def disable(self) -> None:
        self.is_enabled = False
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.save(update_fields=["is_enabled"])

    def record_use(self) -> None:
        self.last_used_at = timezone.now()
        self.use_count = (self.use_count or 0) + 1
        self.save(update_fields=["last_used_at", "use_count"])


class AccessReviewRun(TimeStampedModel):
    """Один прогон access review.

    Раз в N дней celery запускает обзор: для каждой активной роли
    спрашивает у владельца/админа, актуальна ли она. Не подтверждённые
    за T дней — авто-отзыв (опционально).
    """

    class Status(models.TextChoices):
        RUNNING = "running", "Выполняется"
        COMPLETED = "completed", "Завершён"
        CANCELLED = "cancelled", "Отменён"

    started_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.RUNNING, db_index=True,
    )

    total_assignments = models.PositiveIntegerField(default=0)
    confirmed = models.PositiveIntegerField(default=0)
    revoked = models.PositiveIntegerField(default=0)
    pending = models.PositiveIntegerField(default=0)

    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    notes = models.TextField(blank=True)

    class Meta:
        verbose_name = "Прогон access review"
        verbose_name_plural = "Прогоны access review"
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"AccessReview {self.started_at:%Y-%m-%d} [{self.status}]"


class AccessReviewItem(TimeStampedModel):
    """Один пункт обзора — конкретная RoleAssignment."""

    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает подтверждения"
        CONFIRMED = "confirmed", "Подтверждено"
        REVOKED = "revoked", "Отозвано"
        EXPIRED = "expired", "Истекло без ответа"

    run = models.ForeignKey(
        AccessReviewRun, on_delete=models.CASCADE, related_name="items",
    )
    assignment = models.ForeignKey(
        RoleAssignment, on_delete=models.CASCADE,
        related_name="review_items",
    )
    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.PENDING, db_index=True,
    )

    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    comment = models.CharField(max_length=255, blank=True)

    due_by = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        verbose_name = "Пункт access review"
        verbose_name_plural = "Пункты access review"
        ordering = ["-created_at"]
        unique_together = [("run", "assignment")]

    def __str__(self) -> str:
        return f"{self.run} / {self.assignment} [{self.status}]"


class ServiceAccount(TimeStampedModel):
    """Машинный аккаунт.

    Не может логиниться в UI. Используется через API-токены.
    Не имеет ролей в общем смысле — имеет собственный scope,
    который определяет, какие объекты ему доступны.
    """

    class Scope(models.TextChoices):
        READ_ALL = "read_all", "Чтение всего парка"
        READ_DOMAIN = "read_domain", "Чтение домена"
        DEPLOY_DOMAIN = "deploy_domain", "Деплой в домен"
        ADMIN_DOMAIN = "admin_domain", "Администрирование домена"

    name = models.SlugField(max_length=64, unique=True)
    description = models.TextField(blank=True)

    scope = models.CharField(max_length=32, choices=Scope.choices)
    domain = models.ForeignKey(
        "inventory.Domain", null=True, blank=True,
        on_delete=models.CASCADE, related_name="service_accounts",
        help_text="Обязательно, если scope не READ_ALL",
    )

    is_active = models.BooleanField(default=True, db_index=True)
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="service_accounts_created",
    )

    # Учёт использования
    last_used_at = models.DateTimeField(null=True, blank=True)
    use_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Сервисный аккаунт"
        verbose_name_plural = "Сервисные аккаунты"
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} [{self.scope}]"

    def clean(self) -> None:
        if self.scope != self.Scope.READ_ALL and not self.domain_id:
            raise ValidationError(
                f"Для scope={self.scope} нужен домен"
            )
        if self.scope == self.Scope.READ_ALL and self.domain_id:
            raise ValidationError(
                "READ_ALL не должен быть привязан к домену"
            )

    def is_valid(self) -> bool:
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def can_access_domain(self, domain_id: int) -> bool:
        if not self.is_valid():
            return False
        if self.scope == self.Scope.READ_ALL:
            return True
        return self.domain_id == domain_id


class ServiceAccountToken(models.Model):
    """Токен сервисного аккаунта.

    Хранится только sha256-хеш. Plaintext показывается один раз при создании.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        ServiceAccount, on_delete=models.CASCADE, related_name="tokens",
    )

    name = models.CharField(max_length=64, blank=True,
                             help_text="Метка токена (например, «ci-prod»)")
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    token_prefix = models.CharField(max_length=12, db_index=True,
                                     help_text="Первые символы для UI")

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    use_count = models.PositiveIntegerField(default=0)

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    revoked_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = "Токен сервисного аккаунта"
        verbose_name_plural = "Токены сервисных аккаунтов"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["account", "revoked_at"]),
        ]

    def __str__(self) -> str:
        state = "active" if self.is_active else "revoked"
        return f"{self.account.name}/{self.token_prefix}… [{state}]"

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    @classmethod
    def issue(cls, *, account: ServiceAccount, name: str = "",
               created_by=None, expires_at=None) -> tuple["ServiceAccountToken", str]:
        """Создать токен. Возвращает (token_obj, plaintext).

        Plaintext показывается пользователю ОДИН РАЗ и не сохраняется.
        """
        # Префикс для узнаваемости + случайная часть
        raw = secrets.token_urlsafe(32)
        plaintext = f"sa_{account.name}_{raw}"
        token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        prefix = plaintext[:12]

        token = cls.objects.create(
            account=account,
            name=name,
            token_hash=token_hash,
            token_prefix=prefix,
            created_by=created_by,
            expires_at=expires_at,
        )
        return token, plaintext

    @classmethod
    def verify(cls, plaintext: str) -> "ServiceAccountToken | None":
        """Найти активный токен по plaintext."""
        if not plaintext or not plaintext.startswith("sa_"):
            return None
        token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        try:
            token = cls.objects.select_related("account").get(
                token_hash=token_hash,
            )
        except cls.DoesNotExist:
            return None
        if not token.is_active:
            return None
        if not token.account.is_valid():
            return None
        return token

    def touch(self) -> None:
        self.last_used_at = timezone.now()
        self.use_count = (self.use_count or 0) + 1
        self.save(update_fields=["last_used_at", "use_count"])
        # обновить и account
        acc = self.account
        acc.last_used_at = self.last_used_at
        acc.use_count = (acc.use_count or 0) + 1
        acc.save(update_fields=["last_used_at", "use_count"])


class IPAllowlistRule(TimeStampedModel):
    """Правило IP-allowlist.

    Порядок применения:
      1. Если есть правило user → применяется;
      2. Если есть правило role → применяется;
      3. Если есть правило global → применяется;
      4. Если правил нет — доступ разрешён (default allow).

    При наличии хотя бы одного подходящего правила IP проверяется
    против списка; иначе — отказ.

    Исключения: superuser, break-glass-аккаунт, agent API
    (у агентов свой слой auth).
    """

    class Scope(models.TextChoices):
        GLOBAL = "global", "Глобально"
        ROLE = "role", "Роль"
        USER = "user", "Пользователь"

    scope = models.CharField(max_length=16, choices=Scope.choices, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.CASCADE, related_name="ip_rules",
    )
    role = models.CharField(max_length=32, blank=True, db_index=True)

    cidr = models.CharField(max_length=64,
                             help_text="CIDR или одиночный IP (например, 10.0.0.0/8)")
    description = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )

    class Meta:
        verbose_name = "Правило IP-allowlist"
        verbose_name_plural = "Правила IP-allowlist"
        ordering = ["scope", "cidr"]

    def __str__(self) -> str:
        target = self.user.username if self.user_id else (self.role or "global")
        return f"{self.scope}/{target}: {self.cidr}"

    def clean(self) -> None:
        import ipaddress
        try:
            ipaddress.ip_network(self.cidr, strict=False)
        except ValueError as exc:
            raise ValidationError(f"Некорректный CIDR: {self.cidr}") from exc

        if self.scope == self.Scope.USER and not self.user_id:
            raise ValidationError("Для scope=user нужен пользователь")
        if self.scope == self.Scope.ROLE and not self.role:
            raise ValidationError("Для scope=role нужна роль")
        if self.scope == self.Scope.GLOBAL and (self.user_id or self.role):
            raise ValidationError("GLOBAL не должен иметь user/role")