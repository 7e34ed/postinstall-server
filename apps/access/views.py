from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from loguru import logger

from apps.core.utils import get_client_ip

from .aal import AAL
from .cert_parser import ParsedCert
from .checks import InvariantViolation, assert_min_supervisors
from .models import (
    AuthAuditLog,
    Invitation,
    RoleAssignment,
    RoleChangeNotice,
    SuperuserBootstrap,
    log_auth_event,
)
from .roles import Role, ScopeType
from .session_aal import current_aal, set_aal

User = get_user_model()


@require_http_methods(["GET", "POST"])
@login_required
def setup_view(request):
    """Мастер настройки: создание первого SUPERVISOR'а.

    Доступен, пока setup не завершён. Только для superuser.
    """
    bootstrap = SuperuserBootstrap.get()
    if bootstrap.is_setup_complete:
        return redirect("/")

    if not request.user.is_superuser:
        logout(request)
        return redirect("/admin/login/?next=" + reverse("access:setup"))

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        if not username:
            messages.error(request, "Укажите логин.")
        else:
            try:
                with transaction.atomic():
                    user = _get_or_create_user(username, email)
                    _ensure_supervisor_assignment(user, granted_by=request.user)
                    # если уже есть 2+ SUPERVISOR — завершаем setup
                    if _active_supervisors_count() >= 2:
                        SuperuserBootstrap.mark_setup_complete(
                            superuser=request.user,
                        )

                        # Создать break-glass и recovery kit
                        from .recovery_kit import (
                            RecoveryKitData,
                            generate_recovery_codes,
                            write_recovery_kit,
                        )
                        from .services import ensure_break_glass_account

                        bg_user, bg_password = ensure_break_glass_account(
                            created_by=request.user,
                        )
                        if bg_password:
                            codes = generate_recovery_codes(10)
                            kit = RecoveryKitData(
                                username=bg_user.username,
                                password=bg_password,
                                recovery_codes=codes,
                                notes=(
                                    "Break-glass для postinstall-server.\n"
                                    "Сохраните файл в физическом сейфе.\n"
                                    "Пароль также нужен для входа, если потеряны все SUPERVISOR'ы."
                                ),
                            )
                            out_dir = Path(getattr(settings, "ACCESS_RECOVERY_KIT_DIR",
                                                    "/var/lib/postinstall/recovery"))
                            txt, pdf = write_recovery_kit(kit, out_dir)
                            messages.info(
                                request,
                                f"Recovery kit создан: {txt}"
                                + (f" и {pdf}" if pdf else "")
                                + ". Скачайте его сейчас — больше он не будет доступен через UI.",
                            )
                            # redirect на страницу скачивания (см. ниже)
                            return redirect(reverse("access:recovery-kit-download",
                                                    args=[txt.name]))
                        log_auth_event(
                            AuthAuditLog.Event.SETUP_COMPLETED,
                            user=request.user,
                            target_user=user,
                            ip=get_client_ip(request),
                        )
                        messages.success(
                            request,
                            "Setup завершён. Войдите как SUPERVISOR.",
                        )
                        return redirect("/admin/login/")
                    else:
                        messages.success(
                            request,
                            f"SUPERVISOR {username} создан. "
                            "Создайте второго для завершения setup.",
                        )
            except InvariantViolation as exc:
                messages.error(request, str(exc))
            except Exception as exc:
                logger.exception("setup: failed")
                messages.error(request, f"Ошибка: {exc}")

    supervisors = _active_supervisors()
    return render(request, "access/setup.html", {
        "supervisors": supervisors,
        "needed": max(0, 2 - len(supervisors)),
    })


@login_required
@require_http_methods(["GET", "POST"])
def roles_changed_view(request):
    """Экран изменений ролей. Пока не подтверждён — не пускает никуда."""
    notices = list(RoleChangeNotice.objects.filter(
        user=request.user, acknowledged_at__isnull=True,
    ).order_by("created_at"))

    if not notices:
        return redirect("/")

    if request.method == "POST":
        if request.POST.get("action") == "acknowledge":
            now = timezone.now()
            for n in notices:
                n.acknowledged_at = now
                n.save(update_fields=["acknowledged_at"])
            messages.info(
                request,
                "Изменения подтверждены. Требуется повторный вход "
                "для применения новых прав.",
            )
            logout(request)
            return redirect("/admin/login/")

    # Собираем все изменения
    aggregated = []
    for n in notices:
        aggregated.extend(n.changes or [])

    return render(request, "access/roles_changed.html", {
        "notices": notices,
        "changes": aggregated,
    })


# Ввести deprecation, отключить неиспользуемые функци
@require_http_methods(["GET"])
def invite_landing(request, token):
    """Посадочная страница инвайта. Полноценный accept — коммит 2."""
    # Заглушка: проверяем токен, показываем «в разработке».
    from hashlib import sha256
    token_hash = sha256(token.encode()).hexdigest()
    from .models import Invitation
    try:
        inv = Invitation.objects.get(token_hash=token_hash)
    except Invitation.DoesNotExist:
        return render(request, "access/invite_invalid.html", status=404)
    if inv.is_expired:
        return render(request, "access/invite_invalid.html", {
            "reason": "expired",
        }, status=410)
    return render(request, "access/invite_stub.html", {"invitation": inv})


# --- helpers ---

def _get_or_create_user(username: str, email: str):
    try:
        return User.objects.get(username=username)
    except User.DoesNotExist:
        return User.objects.create_user(
            username=username,
            email=email or f"{username}@localhost",
            is_active=True,
            is_staff=False,   # staff-флаг не даёт роли — роль даёт права
            is_superuser=False,
        )


def _ensure_supervisor_assignment(user, *, granted_by):
    RoleAssignment.objects.get_or_create(
        user=user,
        role=Role.SUPERVISOR.value,
        scope_type=ScopeType.GLOBAL.value,
        scope_id=0,
        revoked_at__isnull=True,
        defaults={"granted_by": granted_by},
    )


def _active_supervisors():
    from .permissions import get_active_supervisors
    return get_active_supervisors()


def _active_supervisors_count() -> int:
    return len(_active_supervisors())


@require_http_methods(["GET", "POST"])
@csrf_protect
def invite_accept(request, token: str):
    """Публичная страница принятия инвайта.

    Доступна без логина. Показывает форму регистрации.
    При POST — создаёт User и редиректит на /admin/login/.
    """
    
    from hashlib import sha256

    from .cert_parser import cert_matches_email, parse_cert_from_meta
    from .mtls import extract_client_cert, is_certificate_valid
    from .services import accept_invitation, hash_token

    token_hash = hash_token(token)
    try:
        invitation = Invitation.objects.select_related("invited_by").get(
            token_hash=token_hash,
        )
    except Invitation.DoesNotExist:
        return render(request, "access/invite_invalid.html", {
            "reason": "not_found",
        }, status=404)

    if invitation.status == Invitation.Status.ACCEPTED:
        return render(request, "access/invite_invalid.html", {
            "reason": "already_used",
        }, status=410)

    if invitation.status == Invitation.Status.REVOKED:
        return render(request, "access/invite_invalid.html", {
            "reason": "revoked",
        }, status=410)

    if invitation.status == Invitation.Status.PENDING_APPROVAL:
        return render(request, "access/invite_pending.html", {
            "invitation": invitation,
        })

    if invitation.status == Invitation.Status.REJECTED:
        return render(request, "access/invite_invalid.html", {
            "reason": "rejected",
        }, status=410)

    if invitation.is_expired:
        invitation.status = Invitation.Status.EXPIRED
        invitation.save(update_fields=["status"])
        return render(request, "access/invite_invalid.html", {
            "reason": "expired",
        }, status=410)

    # --- Проверка сертификата (если предъявлен) ---
    presented_cert: ParsedCert | None = None
    cert_ok = False
    cert_reason = "not presented"

    client_cert = extract_client_cert(request)
    if client_cert is not None:
        valid, v_reason = is_certificate_valid(client_cert)
        if valid:
            parsed = parse_cert_from_meta(request.META)
            if parsed is not None:
                presented_cert = parsed
                cert_ok, cert_reason = cert_matches_email(
                    parsed, invitation.email,
                )

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""
        password2 = request.POST.get("password2") or ""
        full_name = (request.POST.get("full_name") or "").strip()
        attach_cert = request.POST.get("attach_cert") == "on"

        errors = []
        if not username:
            errors.append("Логин обязателен")
        if password != password2:
            errors.append("Пароли не совпадают")
        if len(password) < 8:
            errors.append("Пароль минимум 8 символов")
        if len(username) < 3:
            errors.append("Логин минимум 3 символа")
        if attach_cert and not cert_ok:
            errors.append(
                f"Сертификат не подходит для привязки: {cert_reason}"
            )

        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            try:
                # --- Проверка в AD (если настроен) ---
                if invitation.email and cert_ok:
                    try:
                        from apps.inventory.models import Domain
                        from apps.ldap_sync.services import verify_user_active

                        domain = Domain.objects.filter(
                            name=invitation.email.split("@", 1)[1],
                        ).first()
                        if domain:
                            ok, why = verify_user_active(invitation.email, domain=domain)
                            if not ok:
                                errors.append(f"AD: {why}")
                    except Exception as exc:
                        logger.warning(f"accept: LDAP check failed: {exc}")
                
                user = accept_invitation(
                    invitation, token=token,
                    username=username, password=password,
                    full_name=full_name,
                    ip=get_client_ip(request),
                    user_agent=request.user_agent
                    if hasattr(request, "user_agent")
                    else request.META.get("HTTP_USER_AGENT", ""),
                )

                # --- Привязка сертификата, если отмечено ---
                if attach_cert and cert_ok and presented_cert:
                    _attach_cert_to_user(
                        user, presented_cert, invitation,
                        request=request,
                    )

                messages.success(
                    request,
                    "Аккаунт создан. Войдите с указанным логином.",
                )
                return redirect("/admin/login/")
            except (PermissionError, ValueError) as exc:
                messages.error(request, str(exc))

    return render(request, "access/invite_accept.html", {
        "invitation": invitation,
        "token": token,
        "cert_presented": client_cert is not None,
        "cert_ok": cert_ok,
        "cert_reason": cert_reason,
        "cert_cn": presented_cert.cn if presented_cert else "",
    })


def _attach_cert_to_user(user, parsed: ParsedCert, invitation, *, request):
    """Привязать сертификат к пользователю (в рамках accept)."""
    
    from .models import AuthAuditLog, UserCertificate, log_auth_event

    # Дубль?
    if UserCertificate.objects.filter(
        fingerprint_sha256=parsed.fingerprint_sha256,
        is_active=True,
    ).exists():
        logger.warning(
            f"accept: сертификат {parsed.fingerprint_sha256[:16]}… "
            f"уже привязан, пропускаем"
        )
        return

    cert = UserCertificate.objects.create(
        user=user,
        label=f"Enrolled at accept ({parsed.cn or 'cert'})",
        fingerprint_sha256=parsed.fingerprint_sha256,
        subject_dn=parsed.subject_dn,
        issuer_dn=parsed.issuer_dn,
        serial=parsed.serial,
        valid_from=parsed.not_before or None,
        valid_to=parsed.not_after or None,
        is_active=True,
        is_hardware=False,   # пользователь отметит в UI, если это токен
        hardware_kind=UserCertificate.HardwareKind.OTHER,
        created_by=user,
    )
    log_auth_event(
        AuthAuditLog.Event.CERT_ADDED,
        user=user, target_user=user,
        ip=get_client_ip(request),
        detail={
            "label": cert.label,
            "fingerprint": cert.fingerprint_sha256,
            "source": "accept-invite",
            "invitation_id": str(invitation.id),
        },
    )

@require_http_methods(["GET"])
@login_required
def reauth_success(request):
    """Callback после успешного reauthenticate.

    Вызывается как `next` из allauth.mfa. Определяем достигнутый AAL
    и сохраняем его в сессии. Затем редирект на изначальный next.
    """
    
    from allauth.mfa.models import Authenticator

    from .hardware import has_hardware_factor

    user = request.user
    target_aal = request.GET.get("required")
    final_next = request.GET.get("final_next") or "/"

    # Определяем достигнутый AAL
    has_totp = Authenticator.objects.filter(
        user=user, type=Authenticator.Type.TOTP,
    ).exists()
    has_hw = has_hardware_factor(user)

    if has_hw:
        achieved = AAL.AAL3
    elif has_totp:
        achieved = AAL.AAL2
    else:
        achieved = AAL.AAL1

    # Если требуется AAL3, но hardware нет — ограничиваемся AAL2
    # (пока AAL3 не строгий). См. aal3_strict().
    from .aal import aal3_strict
    
    if target_aal == str(int(AAL.AAL3)) and not aal3_strict():
        achieved = AAL.AAL2 if has_totp else AAL.AAL1

    set_aal(request, achieved)
    log_auth_event(
        AuthAuditLog.Event.MFA_SUCCESS,
        user=user, ip=get_client_ip(request),
        detail={"achieved": achieved.label,
                "target": target_aal or "?"},
    )

    if not final_next or final_next == "None":
        final_next = "/"
    return redirect(final_next)


# Перенесено в .hardware
# def _has_hardware_factor(user) -> bool:
#     """Есть ли у пользователя hardware-фактор (WebAuthn, client cert)."""
    
#     from allauth.mfa.models import Authenticator

#     try:
#         if Authenticator.objects.filter(
#             user=user, type="webauthn",
#         ).exists():
#             return True
#     except Exception:
#         pass

#     from .models import UserCertificate
#     return UserCertificate.objects.filter(
#         user=user, is_active=True,
#     ).exists()


@login_required
def recovery_kit_download(request, filename):
    """Скачать recovery kit.

    Доступ: superuser. После первого скачивания — предлагаем удалить файл.
    """
    from django.http import FileResponse, Http404

    if not request.user.is_superuser:
        raise Http404

    kit_dir = Path(getattr(settings, "ACCESS_RECOVERY_KIT_DIR",
                            "/var/lib/postinstall/recovery"))
    path = (kit_dir / filename).resolve()
    # защита от path traversal
    try:
        path.relative_to(kit_dir.resolve())
    except ValueError:
        raise Http404  # noqa: B904

    if not path.exists():
        raise Http404

    log_auth_event(
        AuthAuditLog.Event.SETUP_COMPLETED,   # можно добавить отдельное событие
        user=request.user,
        ip=get_client_ip(request),
        detail={"downloaded": filename},
    )
    return FileResponse(open(path, "rb"),
                         as_attachment=True,
                         filename=filename)


