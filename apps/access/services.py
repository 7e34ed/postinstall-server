"""Сервис-слой access: создание инвайтов, прямых назначений, отзыв ролей."""
from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from secrets import token_urlsafe
from typing import TypeVar

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from loguru import logger

from apps.access.emails import send_invitation_email

from .checks import InvariantViolation, assert_can_revoke
from .models import (
    AccessReviewItem,
    AccessReviewRun,
    AuthAuditLog,
    DirectRoleAssignment,
    Invitation,
    RoleAssignment,
    RoleChangeNotice,
    log_auth_event,
)
from .permissions import active_roles, can_manage_role, get_active_supervisors
from .roles import DUAL_APPROVAL_ROLES, Role, ScopeType

User = get_user_model()
USER = TypeVar(User)

def _invite_ttl_hours(role: str) -> int:
    if role in {r.value for r in DUAL_APPROVAL_ROLES}:
        return getattr(settings, "ACCESS_INVITE_TTL_HOURS_DUAL", 72)
    return getattr(settings, "ACCESS_INVITE_TTL_HOURS", 24)

def hash_token(token: str) -> str:
    """sha256 от токена. Единственное место, где это вычисляется."""
    return sha256(token.encode()).hexdigest()


def _new_token() -> tuple[str, str]:
    """Возвращает (plaintext_token, sha256_hash)."""
    token = token_urlsafe(32)
    return token, hash_token(token)


# ============================================================
#  Инвайты
# ============================================================

def create_invitation(
    *, email: str, role: str,
    scope_type: str, scope_id: int,
    invited_by, valid_until=None, reason: str = "",
) -> tuple[Invitation, str]:
    """Создать инвайт. Возвращает (invitation, plaintext_token).

    Для ролей из DUAL_APPROVAL_ROLES создаётся со статусом
    PENDING_APPROVAL, требуется одобрение второго SUPERVISOR'а.
    """
    if not can_manage_role(invited_by, role,
                           scope_type=scope_type, scope_id=scope_id):
        raise PermissionError(
            f"{invited_by} не может приглашать на роль {role} "
            f"в scope {scope_type}:{scope_id}"
        )

    dual = role in {r.value for r in DUAL_APPROVAL_ROLES}
    token, token_hash = _new_token()

    status = (
        Invitation.Status.PENDING_APPROVAL if dual
        else Invitation.Status.PENDING
    )

    inv = Invitation.objects.create(
        email=email,
        role=role,
        scope_type=scope_type,
        scope_id=scope_id,
        valid_until=valid_until,
        token_hash=token_hash,
        expires_at=timezone.now() + timezone.timedelta(
            hours=_invite_ttl_hours(role),
        ),
        status=status,
        invited_by=invited_by,
    )
    log_auth_event(
        AuthAuditLog.Event.INVITE_CREATED,
        user=invited_by, detail={
            "email": email, "role": role,
            "scope_type": scope_type, "scope_id": scope_id,
            "dual": dual,
        },
    )
    logger.info(f"invitation created: {email} → {role} (dual={dual})")
    return inv, token


def approve_invitation(
    invitation: Invitation, *, by_user,
    ip: str | None = None,
) -> None:
    """Подтвердить инвайт. Применяется для DUAL-инвайтов."""
    if invitation.status != Invitation.Status.PENDING_APPROVAL:
        raise ValueError(
            f"Инвайт не в статусе PENDING_APPROVAL: {invitation.status}"
        )
    if by_user.pk == invitation.invited_by_id:
        raise PermissionError(
            "Подтвердить инвайт должен другой SUPERVISOR"
        )

    if invitation.approval1_by_id is None:
        invitation.approval1_by = by_user
        invitation.approval1_at = timezone.now()
    elif invitation.approval2_by_id is None:
        if by_user.pk == invitation.approval1_by_id:
            raise PermissionError("Нужен третий подтверждающий")
        invitation.approval2_by = by_user
        invitation.approval2_at = timezone.now()
    else:
        raise ValueError("Инвайт уже подтверждён")

    required = invitation.required_approvals()
    approved = sum(1 for x in (invitation.approval1_by_id,
                                invitation.approval2_by_id) if x)

    if approved >= required:
        invitation.status = Invitation.Status.PENDING

    invitation.save()
    log_auth_event(
        AuthAuditLog.Event.INVITE_APPROVED,
        user=by_user, ip=ip,
        detail={"invitation_id": str(invitation.id),
                "approved": approved, "required": required},
    )


def revoke_invitation(
    invitation: Invitation, *, by_user, reason: str = "",
) -> None:
    if invitation.status in (Invitation.Status.ACCEPTED,
                              Invitation.Status.REVOKED):
        raise ValueError("Инвайт уже финализирован")
    invitation.status = Invitation.Status.REVOKED
    invitation.revoked_by = by_user
    invitation.revoked_at = timezone.now()
    invitation.revoke_reason = reason
    invitation.save()
    log_auth_event(
        AuthAuditLog.Event.INVITE_REVOKED,
        user=by_user,
        detail={"invitation_id": str(invitation.id), "reason": reason},
    )


def create_invitation_and_send(
    *, email: str, role: str,
    scope_type: str, scope_id: int,
    invited_by, valid_until=None, reason: str = "",
) -> tuple[Invitation, str, bool]:
    """Создать инвайт и отправить письмо (если не требует consensus).

    Возвращает (invitation, plaintext_token, email_sent).
    Для ADMIN/SUPERVISOR email_sent=False (ждём consensus).
    """
    invitation, token = create_invitation(
        email=email, role=role,
        scope_type=scope_type, scope_id=scope_id,
        invited_by=invited_by, valid_until=valid_until, reason=reason,
    )

    if invitation.status == Invitation.Status.PENDING:
        sent = _send_and_record(invitation, token)
    else:
        sent = False
        logger.info(
            f"invitation {invitation.id}: awaiting consensus, "
            f"email not sent"
        )

    return invitation, token, sent


def _send_and_record(invitation: Invitation, token: str) -> bool:
    ok = send_invitation_email(invitation, token)
    invitation.email_attempts = (invitation.email_attempts or 0) + 1
    if ok:
        invitation.email_sent_at = timezone.now()
        invitation.email_send_error = ""
    else:
        invitation.email_send_error = "send failed"
    invitation.save(update_fields=[
        "email_attempts", "email_sent_at", "email_send_error",
    ])
    return ok


def resend_invitation(invitation: Invitation, *, by_user) -> bool:
    """Переотправить письмо. Только для PENDING-инвайтов."""
    if invitation.status != Invitation.Status.PENDING:
        raise ValueError(
            f"Переотправка доступна только для PENDING, "
            f"текущий статус: {invitation.status}"
        )
    if invitation.is_expired:
        raise ValueError("Инвайт истёк")

    # генерируем новый токен (старый сгорел)
    token, token_hash = _new_token()
    invitation.token_hash = token_hash
    invitation.expires_at = timezone.now() + timedelta(
        hours=_invite_ttl_hours(invitation.role),
    )
    invitation.save(update_fields=["token_hash", "expires_at"])
    return _send_and_record(invitation, token)


def accept_invitation(
    invitation: Invitation, *, token: str,
    username: str, password: str,
    full_name: str = "",
    ip: str | None = None,
    user_agent: str = "",
) -> USER:
    """Принять инвайт: создать User, назначить роль, уведомить.

    Проверки:
      * token совпадает;
      * статус PENDING;
      * не истёк;
      * email не занят другим активным пользователем;
      * username не занят;
      * пароль соответствует политике.
    """
    from .models import RoleAssignment

    token_hash = hash_token(token)
    if token_hash != invitation.token_hash:
        raise PermissionError("Неверный токен")

    if invitation.status != Invitation.Status.PENDING:
        raise ValueError(
            f"Инвайт не в статусе PENDING: {invitation.status}"
        )
    if invitation.is_expired:
        invitation.status = Invitation.Status.EXPIRED
        invitation.save(update_fields=["status"])
        raise ValueError("Инвайт истёк")

    # email-коллизии
    if User.objects.filter(email__iexact=invitation.email,
                            is_active=True).exists():
        raise ValueError(
            f"На email {invitation.email} уже зарегистрирован пользователь"
        )

    # username-коллизии
    if User.objects.filter(username=username).exists():
        raise ValueError(f"Логин {username!r} занят")

    if not password or len(password) < 8:
        raise ValueError("Пароль слишком короткий (минимум 8 символов)")

    with transaction.atomic():
        user = User.objects.create_user(
            username=username,
            email=invitation.email,
            password=password,
            first_name=full_name[:150] if full_name else "",
            is_active=True,
            is_staff=False,
            is_superuser=False,
        )

        RoleAssignment.objects.create(
            user=user,
            role=invitation.role,
            scope_type=invitation.scope_type,
            scope_id=invitation.scope_id,
            valid_until=invitation.valid_until,
            granted_by=invitation.invited_by,
        )

        invitation.status = Invitation.Status.ACCEPTED
        invitation.accepted_by = user
        invitation.accepted_at = timezone.now()
        invitation.save(update_fields=["status", "accepted_by", "accepted_at"])

        log_auth_event(
            AuthAuditLog.Event.INVITE_ACCEPTED,
            user=user, ip=ip,
            user_agent=user_agent,
            detail={
                "invitation_id": str(invitation.id),
                "role": invitation.role,
                "scope_type": invitation.scope_type,
                "scope_id": invitation.scope_id,
            },
        )

    logger.info(
        f"invitation {invitation.id} accepted: {username} "
        f"({invitation.role})"
    )
    return user


def expire_stale_invitations() -> int:
    """Помечает истёкшие инвайты. Для celery beat."""
    now = timezone.now()
    n = Invitation.objects.filter(
        status__in=[Invitation.Status.PENDING,
                    Invitation.Status.PENDING_APPROVAL],
        expires_at__lt=now,
    ).update(status=Invitation.Status.EXPIRED)
    if n:
        logger.info(f"invitations: expired {n} stale records")
    return n

# ============================================================
#  Прямое назначение
# ============================================================

def initiate_direct_assignment(
    *, target_user, role: str,
    scope_type: str, scope_id: int,
    by_user, valid_until=None, reason: str = "",
) -> DirectRoleAssignment:
    if not can_manage_role(by_user, role,
                           scope_type=scope_type, scope_id=scope_id):
        raise PermissionError(
            f"{by_user} не может назначать {role} "
            f"в scope {scope_type}:{scope_id}"
        )

    existing = RoleAssignment.objects.filter(
        user=target_user, role=role,
        scope_type=scope_type, scope_id=scope_id,
        revoked_at__isnull=True,
    ).exists()
    if existing:
        raise ValueError("Такая роль уже активна у пользователя")

    dual = role in {r.value for r in DUAL_APPROVAL_ROLES}

    da = DirectRoleAssignment.objects.create(
        target_user=target_user,
        role=role, scope_type=scope_type, scope_id=scope_id,
        valid_until=valid_until,
        initiated_by=by_user,
        reason=reason,
    )

    if not dual:
        # сразу применяем
        _apply_direct_assignment(da, approver=by_user)
    else:
        # ждём второго
        da.approval1_by = by_user
        da.approval1_at = timezone.now()
        da.save(update_fields=["approval1_by", "approval1_at"])

    return da


def approve_direct_assignment(
    da: DirectRoleAssignment, *, by_user,
) -> None:
    if da.status != DirectRoleAssignment.Status.PENDING:
        raise ValueError(f"Назначение в статусе {da.status}")
    if by_user.pk == da.initiated_by_id:
        raise PermissionError("Нужен другой подтверждающий")

    required = da.required_approvals()
    if required >= 2:
        if da.approval2_by_id is None:
            da.approval2_by = by_user
            da.approval2_at = timezone.now()
            da.save(update_fields=["approval2_by", "approval2_at"])

    _apply_direct_assignment(da, approver=by_user)


def _apply_direct_assignment(da: DirectRoleAssignment, *, approver) -> None:
    with transaction.atomic():
        ra, created = RoleAssignment.objects.get_or_create(
            user=da.target_user,
            role=da.role,
            scope_type=da.scope_type,
            scope_id=da.scope_id,
            revoked_at__isnull=True,
            defaults={
                "granted_by": da.initiated_by,
                "valid_until": da.valid_until,
            },
        )
        da.status = DirectRoleAssignment.Status.EXECUTED
        da.executed_at = timezone.now()
        da.save(update_fields=["status", "executed_at"])

        RoleChangeNotice.objects.create(
            user=da.target_user,
            changes=[{
                "kind": "grant",
                "role": da.role,
                "scope_type": da.scope_type,
                "scope_id": da.scope_id,
                "reason": da.reason,
            }],
            reason=da.reason,
            triggered_by=approver,
        )
        log_auth_event(
            AuthAuditLog.Event.ROLE_GRANTED,
            user=approver, target_user=da.target_user,
            detail={"role": da.role, "scope_type": da.scope_type,
                    "scope_id": da.scope_id, "source": "direct"},
        )


# ============================================================
#  Отзыв роли
# ============================================================

def revoke_role(
    assignment: RoleAssignment, *, by_user, reason: str = "",
) -> None:
    """Отозвать RoleAssignment с проверкой инвариантов."""
    if not can_manage_role(by_user, assignment.role,
                           scope_type=assignment.scope_type,
                           scope_id=assignment.scope_id):
        raise PermissionError("Нет прав на отзыв этой роли")

    assert_can_revoke(assignment)

    assignment.revoked_at = timezone.now()
    assignment.revoked_by = by_user
    assignment.revoke_reason = reason
    assignment.save(update_fields=["revoked_at", "revoked_by",
                                    "revoke_reason"])

    RoleChangeNotice.objects.create(
        user=assignment.user,
        changes=[{
            "kind": "revoke",
            "role": assignment.role,
            "scope_type": assignment.scope_type,
            "scope_id": assignment.scope_id,
            "reason": reason,
        }],
        reason=reason, triggered_by=by_user,
    )
    log_auth_event(
        AuthAuditLog.Event.ROLE_REVOKED,
        user=by_user, target_user=assignment.user,
        detail={"role": assignment.role, "reason": reason},
    )


# ============================================================
#  Break-glass
# ============================================================

def ensure_break_glass_account(*, created_by) -> tuple:
    """Создать break-glass-учётку при bootstrap.

    Возвращает (user, password). Пароль нужно сохранить в recovery kit
    и физический сейф. Пользователь по умолчанию неактивен.
    """
    from django.contrib.auth import get_user_model

    from .recovery_kit import generate_password

    User = get_user_model()
    username = "break-glass"

    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            "email": "break-glass@localhost",
            "is_staff": False,
            "is_superuser": False,
            "is_active": False,
            "first_name": "Break-glass",
        },
    )
    if not created:
        # уже есть — не перезаписываем пароль
        return user, ""

    password = generate_password(24)
    user.set_password(password)
    user.save()

    from .models import BreakGlassAccount
    BreakGlassAccount.create_default(user=user, password=password)
    logger.info("access: break-glass account created")

    return user, password


def can_enable_break_glass(*, hours: int = 24) -> tuple[bool, str]:
    """Проверка условий для включения break-glass.

    Возвращает (ok, reason).
    """
    live = _supervisor_activity_recent(hours=hours)
    if live:
        names = ", ".join(u.username for u in live[:5])
        if len(live) > 5:
            names += f" и ещё {len(live) - 5}"
        return False, (
            f"Есть активные SUPERVISOR'ы за последние {hours} ч: {names}. "
            f"Break-glass не требуется. Для обхода используйте --force."
        )
    return True, "нет активных SUPERVISOR'ов за указанный период"


def enable_break_glass(
    *,
    by_user,
    reason: str = "",
    force: bool = False,
    check_hours: int = 24,
) -> None:
    """Включить break-glass.

    По умолчанию отказывается, если есть «живые» SUPERVISOR'ы.
    force=True — обход с громким аудитом (для аварийного случая).
    """
    from .models import BreakGlassAccount

    account = BreakGlassAccount.get()
    if account is None:
        raise ValueError("Break-glass account не создан")

    ok, why = can_enable_break_glass(hours=check_hours)
    if not ok and not force:
        log_auth_event(
            AuthAuditLog.Event.BREAK_GLASS_ENABLED,
            user=by_user, target_user=account.user,
            success=False,
            error="refused: supervisors active",
            detail={"live_supervisors": why},
        )
        raise PermissionError(f"Break-glass отказ: {why}")

    account.enable(by_user=by_user, reason=reason)

    log_auth_event(
        AuthAuditLog.Event.BREAK_GLASS_ENABLED,
        user=by_user, target_user=account.user,
        detail={
            "reason": reason,
            "hours": account.auto_disable_after_hours,
            "force": force,
            "check_hours": check_hours,
            "live_supervisors": why,
        },
    )
    logger.warning(
        f"access: BREAK-GLASS ENABLED (force={force}) "
        f"by {(by_user.username if by_user else 'system')}: {reason}"
    )

    try:
        _notify_supervisors_break_glass_enabled(account, by_user, reason)
    except Exception:
        logger.exception("access: notify supervisors failed")


def disable_break_glass(*, by_user=None) -> None:
    from .models import BreakGlassAccount
    account = BreakGlassAccount.get()
    if account is None:
        return

    account.disable()
    log_auth_event(
        AuthAuditLog.Event.BREAK_GLASS_DISABLED,
        user=by_user, target_user=account.user,
    )
    actor = by_user.username if by_user else "system (manage.py)"
    logger.info(f"access: break-glass disabled by {actor}")


def record_break_glass_use(*, user) -> None:
    """Вызывается при логине break-glass-пользователя."""
    
    from .models import BreakGlassAccount
    
    account = BreakGlassAccount.get()
    if account and account.user_id == user.pk and account.is_currently_active():
        account.record_use()
        log_auth_event(
            AuthAuditLog.Event.BREAK_GLASS_USED,
            user=user,
        )
        logger.warning(f"access: BREAK-GLASS USED by {user.username}")


def _notify_supervisors_break_glass_enabled(account, by_user, reason):
    from django.conf import settings
    from django.core.mail import send_mail

    supervisors = get_active_supervisors()
    excluded_pk = by_user.pk if by_user else None
    emails = [u.email for u in supervisors
              if u.email and u.pk != excluded_pk]
    if not emails:
        return

    actor = by_user.username if by_user else "system (manage.py)"
    subject = "[postinstall] Break-glass активирован"
    body = (
        f"Break-glass-учётка активирована.\n\n"
        f"Кто: {actor}\n"
        f"Когда: {timezone.now():%Y-%m-%d %H:%M:%S}\n"
        f"Причина: {reason or '(не указана)'}\n"
        f"Авто-выключение через: {account.auto_disable_after_hours} ч.\n\n"
        f"Аудит: /admin/access/authauditlog/"
    )
    send_mail(
        subject, body,
        settings.DEFAULT_FROM_EMAIL,
        emails,
        fail_silently=True,
    )


# ============================================================
#  Auto-disable break-glass (для celery beat)
# ============================================================

def auto_disable_expired_break_glass() -> int:
    """Выключить break-glass, если истёк auto-disable таймер."""
    
    from .models import BreakGlassAccount

    account = BreakGlassAccount.get()
    if account is None or not account.is_enabled:
        return 0
    if account.is_currently_active():
        return 0

    account.disable()
    log_auth_event(
        AuthAuditLog.Event.BREAK_GLASS_DISABLED,
        detail={"reason": "auto-expire"},
    )
    logger.warning("access: break-glass auto-disabled (expired)")
    return 1


# ============================================================
#  Access review
# ============================================================

def start_access_review(*, triggered_by=None, due_in_days: int = 14,
                        notes: str = "") -> "AccessReviewRun":
    """Создать прогон review. Включает все активные RoleAssignment."""
    
    # from .models import AccessReviewItem, AccessReviewRun, RoleAssignment, AuthAuditLog

    run = AccessReviewRun.objects.create(
        triggered_by=triggered_by,
        notes=notes,
    )
    due_by = timezone.now() + timezone.timedelta(days=due_in_days)

    active = RoleAssignment.objects.filter(revoked_at__isnull=True)
    # исключаем просроченные valid_until
    now = timezone.now()
    active = [ra for ra in active if not (ra.valid_until and ra.valid_until < now)]

    for ra in active:
        AccessReviewItem.objects.create(
            run=run, assignment=ra,
            status=AccessReviewItem.Status.PENDING,
            due_by=due_by,
        )

    run.total_assignments = len(active)
    run.pending = len(active)
    run.save(update_fields=["total_assignments", "pending"])

    log_auth_event(
        AuthAuditLog.Event.ACCESS_REVIEW_STARTED,
        user=triggered_by,
        detail={"run_id": str(run.id), "total": len(active),
                "due_in_days": due_in_days},
    )
    logger.info(f"access: review run {run.id} started, {len(active)} items")
    return run


def confirm_review_item(item, *, by_user, comment: str = "") -> None:
    """Подтвердить актуальность роли."""

    # from .models import AccessReviewItem

    if item.status != AccessReviewItem.Status.PENDING:
        raise ValueError(f"Item уже обработан: {item.status}")

    item.status = AccessReviewItem.Status.CONFIRMED
    item.reviewed_by = by_user
    item.reviewed_at = timezone.now()
    item.comment = comment
    item.save(update_fields=["status", "reviewed_by", "reviewed_at", "comment"])

    run = item.run
    run.confirmed += 1
    run.pending = max(0, run.pending - 1)
    run.save(update_fields=["confirmed", "pending"])

    log_auth_event(
        AuthAuditLog.Event.ACCESS_REVIEW_CONFIRMED,
        user=by_user, target_user=item.assignment.user,
        detail={"run_id": str(run.id),
                "role": item.assignment.role},
    )


def revoke_review_item(item, *, by_user, comment: str = "") -> None:
    """Отозвать роль по результатам review."""
    # from .models import AccessReviewItem

    if item.status != AccessReviewItem.Status.PENDING:
        raise ValueError(f"Item уже обработан: {item.status}")

    # отзываем роль
    revoke_role(item.assignment, by_user=by_user,
                reason=f"access review: {comment}"[:255])

    item.status = AccessReviewItem.Status.REVOKED
    item.reviewed_by = by_user
    item.reviewed_at = timezone.now()
    item.comment = comment
    item.save(update_fields=["status", "reviewed_by", "reviewed_at", "comment"])

    run = item.run
    run.revoked += 1
    run.pending = max(0, run.pending - 1)
    run.save(update_fields=["revoked", "pending"])

    log_auth_event(
        AuthAuditLog.Event.ACCESS_REVIEW_REVOKED,
        user=by_user, target_user=item.assignment.user,
        detail={"run_id": str(run.id),
                "role": item.assignment.role},
    )


def expire_overdue_review_items() -> int:
    """Помечает просроченные items как expired. Авто-отзыв не делаем —
    только уведомляем, чтобы не отзывать роли без явного решения."""
    # from .models import AccessReviewItem

    now = timezone.now()
    n = AccessReviewItem.objects.filter(
        status=AccessReviewItem.Status.PENDING,
        due_by__lt=now,
    ).update(status=AccessReviewItem.Status.EXPIRED)

    # обновить счётчики runs
    for item in AccessReviewItem.objects.filter(
        status=AccessReviewItem.Status.EXPIRED,
        run__status="running",
    ).select_related("run"):
        run = item.run
        run.pending = max(0, run.pending - 1)
        run.save(update_fields=["pending"])
        if run.pending == 0:
            run.status = "completed"
            run.finished_at = now
            run.save(update_fields=["status", "finished_at"])

    if n:
        logger.info(f"access: {n} review items expired")
    return n


def _supervisor_activity_recent(hours: int = 24) -> list:
    """Вернуть SUPERVISOR'ов с активностью за N часов.

    «Живой» SUPERVISOR = активная роль SUPERVISOR + активность
    (UserActivity.last_activity_at) в пределах окна.
    """
    from datetime import timedelta

    from django.utils import timezone

    cutoff = timezone.now() - timedelta(hours=hours)
    result = []
    for u in get_active_supervisors():
        try:
            last = u.activity.last_activity_at
        except Exception:
            last = None
        if last is None:
            continue
        if last >= cutoff:
            result.append(u)
    return result
