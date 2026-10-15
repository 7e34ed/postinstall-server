"""UI управления ролями (не в Django admin, а в основном UI)."""
from __future__ import annotations

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from apps.access.decorators import require_roles
from apps.core.decorators import rate_limit
from apps.core.utils import get_client_ip, resolve_scope_object
from apps.inventory.models import Domain, Host, HostSet

from .emails import _scope_label
from .models import (
    AuthAuditLog,
    DirectRoleAssignment,
    Invitation,
    RoleAssignment,
    RoleChangeNotice,
    log_auth_event,
)
from .permissions import (
    active_roles,
    can_manage_role,
    get_active_supervisors,
    is_supervisor,
    roles_user_can_manage,
)
from .roles import ROLE_LABELS, SCOPE_LABELS, Role, ScopeType
from .services import (
    approve_direct_assignment,
    initiate_direct_assignment,
    revoke_role,
)

User = get_user_model()


@require_roles("supervisor")
def roles_list(request: HttpRequest) -> HttpResponse:
    user = request.user
    if not (user.is_superuser or is_supervisor(user)):
        return HttpResponseForbidden("Только SUPERVISOR")

    q = (request.GET.get("q") or "").strip()
    qs = RoleAssignment.objects.filter(revoked_at__isnull=True) \
        .select_related("user", "granted_by")
    if q:
        qs = qs.filter(
            Q(user__username__icontains=q) | Q(user__email__icontains=q)
        )
    qs = qs.order_by("-granted_at")[:500]

    # разворачиваем scope в читаемые названия
    rows = []
    for ra in qs:
        rows.append({
            "assignment": ra,
            "user": ra.user,
            "role_label": ROLE_LABELS.get(ra.role, ra.role),
            "scope_label": SCOPE_LABELS.get(ra.scope_type, ra.scope_type),
            "scope_obj": resolve_scope_object(ra.scope_type, ra.scope_id),
        })

    pending = DirectRoleAssignment.objects.filter(
        status=DirectRoleAssignment.Status.PENDING,
    ).select_related("target_user", "initiated_by")

    return render(request, "access/roles_list.html", {
        "rows": rows, "q": q, "pending": pending,
    })


# def _resolve_scope(scope_type: str, scope_id: int):
#     if scope_type == ScopeType.GLOBAL.value:
#         return None
#     try:
#         if scope_type == ScopeType.DOMAIN.value:
#             return Domain.objects.get(pk=scope_id)
#         if scope_type == ScopeType.HOST_SET.value:
#             return HostSet.objects.get(pk=scope_id)
#         if scope_type == ScopeType.HOST.value:
#             return Host.objects.get(pk=scope_id)
#     except Exception:
#         return None
#     return None


@login_required
@rate_limit(limit=30, window=3600, key_prefix="secrets_backend_change")
@require_http_methods(["GET", "POST"])
def role_assign(request: HttpRequest) -> HttpResponse:
    from .permissions import (
        can_manage_role,
        is_supervisor,
        roles_user_can_manage,
    )
    from .roles import ROLE_LABELS, Role, ScopeType

    user = request.user
    if not (user.is_superuser or is_supervisor(user)):
        return HttpResponseForbidden("Только SUPERVISOR")

    # --- GET: подготовить форму ---
    if request.method == "GET":
        domains = list(Domain.objects.all().values("pk", "name"))
        host_sets = list(HostSet.objects.all().values("pk", "name", "domain_id"))
        hosts = list(Host.objects.all().values("pk", "hostname",
                                                "domain_id", "host_set_id"))

        manageable: set[str] = set()
        if user.is_superuser:
            manageable = {r.value for r in Role if r != Role.SERVICE}
        else:
            manageable |= roles_user_can_manage(
                user, scope_type=ScopeType.GLOBAL.value, scope_id=0,
            )
            for d in Domain.objects.all():
                manageable |= roles_user_can_manage(
                    user, scope_type=ScopeType.DOMAIN.value, scope_id=d.pk,
                )

        return render(request, "access/role_assign.html", {
            "scopes": {
                "domain": domains,
                "host_set": host_sets,
                "host": hosts,
            },
            "available_roles": [
                {"value": r.value, "label": ROLE_LABELS.get(r.value, r.value)}
                for r in Role if r.value in manageable
            ],
        })

    # --- POST ---
    username = (request.POST.get("username") or "").strip()
    role = (request.POST.get("role") or "").strip()
    scope_type = (request.POST.get("scope_type") or "").strip()
    scope_id_raw = request.POST.get("scope_id") or "0"
    reason = (request.POST.get("reason") or "").strip()

    try:
        scope_id = int(scope_id_raw)
    except ValueError:
        messages.error(request, "Некорректный scope_id.")
        return redirect(reverse("access:role-assign"))

    if not can_manage_role(user, role,
                            scope_type=scope_type, scope_id=scope_id):
        messages.error(
            request,
            f"Нет прав выдавать роль «{role}» "
            f"в scope {scope_type}:{scope_id}.",
        )
        return redirect(reverse("access:roles-list"))

    try:
        target_user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, f"Пользователь {username!r} не найден.")
        return redirect(reverse("access:role-assign"))

    try:
        da = initiate_direct_assignment(
            target_user=target_user, role=role,
            scope_type=scope_type, scope_id=scope_id,
            by_user=user, reason=reason,
        )
        if da.status == DirectRoleAssignment.Status.EXECUTED:
            messages.success(request, "Роль назначена.")
        else:
            messages.info(
                request,
                "Назначение инициировано. Требуется подтверждение "
                "второго SUPERVISOR'а.",
            )
        return redirect(reverse("access:roles-list"))
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))

    return redirect(reverse("access:role-assign"))


@require_roles("supervisor")
@rate_limit(limit=30, window=3600, key_prefix="secrets_backend_change")
@require_http_methods(["POST"])
def role_revoke(request: HttpRequest, pk: int) -> HttpResponse:
    ra = get_object_or_404(RoleAssignment, pk=pk)
    reason = (request.POST.get("reason") or "").strip()
    try:
        revoke_role(ra, by_user=request.user, reason=reason)
        messages.success(request, f"Роль {ra.role} отозвана у {ra.user}.")
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))
    return redirect(reverse("access:roles-list"))


@require_roles("supervisor")
@require_http_methods(["POST"])
def direct_approve(request: HttpRequest, pk) -> HttpResponse:
    da = get_object_or_404(DirectRoleAssignment, pk=pk)
    try:
        approve_direct_assignment(da, by_user=request.user)
        messages.success(request, "Назначение подтверждено и применено.")
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))
    return redirect(reverse("access:roles-list"))


@require_roles("supervisor", "admin")
def invites_list(request: HttpRequest) -> HttpResponse:
    from .models import Invitation

    user = request.user
    if not (user.is_superuser or is_supervisor(user)):
        # ADMIN может видеть только свои инвайты
        qs = Invitation.objects.filter(invited_by=user)
    else:
        qs = Invitation.objects.all()

    status_filter = request.GET.get("status", "")
    if status_filter:
        qs = qs.filter(status=status_filter)

    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(email__icontains=q)

    qs = qs.select_related("invited_by", "approval1_by", "approval2_by",
                           "accepted_by").order_by("-created_at")

    paginator = Paginator(qs, 50)
    page = paginator.get_page(request.GET.get("page"))

    rows = []
    for inv in page:
        rows.append({
            "invitation": inv,
            "scope_label": _scope_label(inv.scope_type, inv.scope_id),
            "is_expired": inv.is_expired,
            "approvals": inv.approvals_count,
            "required_approvals": inv.required_approvals(),
        })

    pending_approval = Invitation.objects.filter(
        status=Invitation.Status.PENDING_APPROVAL,
    ).select_related("invited_by").order_by("-created_at")

    return render(request, "access/invites_list.html", {
        "rows": rows,
        "page": page,
        "q": q,
        "status_filter": status_filter,
        "statuses": Invitation.Status.choices,
        "pending_approval": pending_approval,
    })

        
@require_roles("supervisor", "admin")
@rate_limit(limit=30, window=3600, key_prefix="secrets_backend_change")
@require_http_methods(["GET", "POST"])
def invite_create(request: HttpRequest) -> HttpResponse:
    from .roles import ROLE_LABELS, Role
    from .services import create_invitation_and_send

    user = request.user
    if not (user.is_superuser or is_supervisor(user)):
        # ADMIN может приглашать только OPERATOR/VIEWER
        pass

    # список доступных ролей в контексте
    manageable = roles_user_can_manage(
        user, scope_type=ScopeType.GLOBAL.value, scope_id=0,
    ) or set()
    # добав им для доменного scope
    for d in Domain.objects.all():
        manageable |= roles_user_can_manage(
            user, scope_type=ScopeType.DOMAIN.value, scope_id=d.pk,
        )

    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        role = (request.POST.get("role") or "").strip()
        scope_type = (request.POST.get("scope_type") or "").strip()
        scope_id_raw = request.POST.get("scope_id") or "0"
        reason = (request.POST.get("reason") or "").strip()

        try:
            scope_id = int(scope_id_raw)
        except ValueError:
            messages.error(request, "Некорректный scope_id.")
            return redirect(reverse("access:invite-create"))

        if not email:
            messages.error(request, "Email обязателен.")
        else:
            try:
                inv, _token, sent = create_invitation_and_send(
                    email=email, role=role,
                    scope_type=scope_type, scope_id=scope_id,
                    invited_by=user, reason=reason,
                )
                if inv.status == Invitation.Status.PENDING_APPROVAL:
                    messages.info(
                        request,
                        f"Инвайт создан (ID {str(inv.id)[:8]}). "
                        "Требует подтверждения второго SUPERVISOR'а — "
                        "письмо уйдёт после approval."
                    )
                elif sent:
                    messages.success(
                        request,
                        f"Инвайт отправлен на {email}."
                    )
                else:
                    messages.warning(
                        request,
                        "Инвайт создан, но письмо отправить не удалось. "
                        "Проверьте SMTP и переотправьте."
                    )
                return redirect(reverse("access:invites-list"))
            except (PermissionError, ValueError) as exc:
                messages.error(request, str(exc))

    # для формы
    domains = list(Domain.objects.all().values("pk", "name"))
    host_sets = list(HostSet.objects.all().values("pk", "name",
                                                   "domain_id"))
    hosts = list(Host.objects.all().values("pk", "hostname",
                                            "domain_id", "host_set_id"))

    return render(request, "access/invite_form.html", {
        "available_roles": [
            {"value": r.value, "label": ROLE_LABELS.get(r.value, r.value)}
            for r in Role if r.value in manageable
        ],
        "domains": domains,
        "host_sets": host_sets,
        "hosts": hosts,
    })


@require_roles("supervisor")
@rate_limit(limit=30, window=3600, key_prefix="secrets_backend_change")
@require_http_methods(["POST"])
def invite_approve(request: HttpRequest, pk) -> HttpResponse:
    from .models import Invitation as _Inv
    from .services import _new_token, approve_invitation, resend_invitation

    try:
        inv = _Inv.objects.get(pk=pk)
    except _Inv.DoesNotExist:
        messages.error(request, "Инвайт не найден.")
        return redirect(reverse("access:invites-list"))

    try:
        approve_invitation(inv, by_user=request.user,
                           ip=get_client_ip(request))
        inv.refresh_from_db()

        if inv.status == Invitation.Status.PENDING:
            # consensus достигнут — отправляем письмо
            # нужен новый токен, т.к. исходный уже не сохранён
            token, token_hash = _new_token()
            inv.token_hash = token_hash
            inv.save(update_fields=["token_hash"])
            from .services import _send_and_record
            sent = _send_and_record(inv, token)
            if sent:
                messages.success(
                    request,
                    f"Инвайт подтверждён, письмо отправлено на {inv.email}."
                )
            else:
                messages.warning(
                    request,
                    "Инвайт подтверждён, но письмо не отправлено. "
                    "Переотправьте вручную."
                )
        else:
            messages.info(
                request,
                f"Подтверждений: {inv.approvals_count}/"
                f"{inv.required_approvals()}."
            )
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))

    return redirect(reverse("access:invites-list"))


@require_roles("supervisor", "admin")
@require_http_methods(["POST"])
def invite_revoke(request: HttpRequest, pk) -> HttpResponse:
    from .models import Invitation as _Inv
    from .services import revoke_invitation

    try:
        inv = _Inv.objects.get(pk=pk)
    except _Inv.DoesNotExist:
        messages.error(request, "Инвайт не найден.")
        return redirect(reverse("access:invites-list"))

    reason = (request.POST.get("reason") or "").strip()
    try:
        revoke_invitation(inv, by_user=request.user, reason=reason)
        messages.success(request, "Инвайт отозван.")
    except ValueError as exc:
        messages.error(request, str(exc))

    return redirect(reverse("access:invites-list"))


@require_roles("supervisor", "admin")
@require_http_methods(["POST"])
def invite_resend(request: HttpRequest, pk) -> HttpResponse:
    from .models import Invitation as _Inv
    from .services import resend_invitation

    try:
        inv = _Inv.objects.get(pk=pk)
    except _Inv.DoesNotExist:
        messages.error(request, "Инвайт не найден.")
        return redirect(reverse("access:invites-list"))

    try:
        sent = resend_invitation(inv, by_user=request.user)
        if sent:
            messages.success(request, f"Письмо переотправлено на {inv.email}.")
        else:
            messages.warning(request, "Письмо не отправилось.")
    except ValueError as exc:
        messages.error(request, str(exc))

    return redirect(reverse("access:invites-list"))


@require_roles("supervisor")
@rate_limit(limit=5, window=3600, key_prefix="secrets_backend_change")
@require_http_methods(["GET", "POST"])
def high_security_page(request: HttpRequest) -> HttpResponse:
    from .aal import AAL
    from .high_security import (
        is_high_security_enabled,
        set_high_security,
    )
    from .permissions import is_supervisor
    from .session_aal import current_aal

    if not is_supervisor(request.user):
        return HttpResponseForbidden("Только SUPERVISOR")

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "toggle":
            try:
                new_state = not is_high_security_enabled()
                set_high_security(
                    new_state, by_user=request.user,
                    ip=get_client_ip(request),
                )
                messages.success(
                    request,
                    f"Усиленный режим {'включён' if new_state else 'выключен'}.",
                )
            except PermissionError as exc:
                messages.error(request, str(exc))
            return HttpResponseRedirect(request.path)

    return render(request, "access/high_security.html", {
        "enabled": is_high_security_enabled(),
        "current_aal": current_aal(request).label,
    })


@login_required
def security_center(request: HttpRequest) -> HttpResponse:
    """Расширенная страница безопасности: AAL, MFA, сертификаты, режим."""
    from allauth.mfa.models import Authenticator

    from .high_security import is_high_security_enabled, requires_hardware_for
    from .models import UserCertificate
    from .session_aal import current_aal, current_aal_timestamp, is_aal_fresh

    user = request.user
    totp = Authenticator.objects.filter(
        user=user, type=Authenticator.Type.TOTP,
    ).first()
    recovery = Authenticator.objects.filter(
        user=user, type=Authenticator.Type.RECOVERY_CODES,
    ).first()
    certificates = UserCertificate.objects.filter(user=user, is_active=True)

    return render(request, "access/my_security.html", {
        "has_totp": bool(totp),
        "totp": totp,
        "recovery": recovery,
        "certificates": certificates,
        "current_aal": current_aal(request),
        "current_aal_at": current_aal_timestamp(request),
        "aal_fresh": is_aal_fresh(request),
        "high_security": is_high_security_enabled(),
        "needs_hardware": requires_hardware_for(user),
    })


@login_required
@require_http_methods(["GET", "POST"])
def certificates_list(request: HttpRequest) -> HttpResponse:
    from .forms import CertificateEnrollForm
    from .models import UserCertificate
    from .mtls import allow_self_enroll

    user = request.user
    certs = UserCertificate.objects.filter(user=user).order_by("-created_at")

    if request.method == "POST":
        if not (allow_self_enroll() or user.is_superuser):
            messages.error(request, "Самостоятельная привязка запрещена.")
            return redirect(reverse("access:certificates-list"))

        form = CertificateEnrollForm(request.POST)
        if form.is_valid():
            cert = UserCertificate.objects.create(
                user=user,
                label=form.cleaned_data["label"],
                fingerprint_sha256=form.cleaned_data["fingerprint"],
                subject_dn=form.cleaned_data["subject_dn"] or "",
                valid_to=form.cleaned_data["valid_to"],
                is_active=True,
                created_by=user,
            )
            log_auth_event(
                AuthAuditLog.Event.CERT_ADDED,
                user=user, target_user=user,
                ip=get_client_ip(request),
                detail={
                    "label": cert.label,
                    "fingerprint": cert.fingerprint_sha256,
                },
            )
            messages.success(
                request,
                f"Сертификат «{cert.label}» привязан. "
                "Для активации перезайдите с использованием mTLS."
            )
            return redirect(reverse("access:certificates-list"))
    else:
        form = CertificateEnrollForm()

    return render(request, "access/certificates_list.html", {
        "certificates": certs,
        "form": form,
        "allow_self_enroll": allow_self_enroll(),
    })


@login_required
@require_http_methods(["POST"])
def certificate_revoke(request: HttpRequest, pk: int) -> HttpResponse:
    from .models import UserCertificate

    try:
        cert = UserCertificate.objects.get(pk=pk)
    except UserCertificate.DoesNotExist:
        messages.error(request, "Сертификат не найден.")
        return redirect(reverse("access:certificates-list"))

    if cert.user_id != request.user.pk and not is_supervisor(request.user):
        return HttpResponseForbidden(
            "Отозвать сертификат может только владелец или SUPERVISOR"
        )

    reason = (request.POST.get("reason") or "").strip()
    cert.is_active = False
    cert.revoked_at = timezone.now()
    cert.revoked_reason = reason
    cert.save(update_fields=["is_active", "revoked_at", "revoked_reason"])

    log_auth_event(
        AuthAuditLog.Event.CERT_REVOKED,
        user=request.user, target_user=cert.user,
        ip=get_client_ip(request),
        detail={"fingerprint": cert.fingerprint_sha256,
                "reason": reason},
    )
    messages.success(request, f"Сертификат «{cert.label}» отозван.")
    return redirect(reverse("access:certificates-list"))


@require_roles("supervisor")
@require_http_methods(["GET", "POST"])
def radius_page(request: HttpRequest) -> HttpResponse:
    from .auth_backends import build_config_from_constance, test_connection
    from .models import UserAuthSettings

    if not is_supervisor(request.user):
        return HttpResponseForbidden("Только SUPERVISOR")

    result = None
    if request.method == "POST":
        if request.POST.get("action") == "test":
            cfg = build_config_from_constance()
            if cfg is None:
                messages.error(
                    request,
                    "RADIUS выключен или не настроен (host/secret пусты).",
                )
            else:
                test_user = request.POST.get("username") or "radius-test"
                test_pass = request.POST.get("password") or "wrong"
                r = test_connection(cfg, username=test_user, password=test_pass)
                if r is None:
                    messages.error(
                        request,
                        "RADIUS недоступен. Проверьте host, порт, secret.",
                    )
                else:
                    if r.accepted:
                        messages.success(
                            request,
                            f"RADIUS ответил: Access-Accept "
                            f"({r.message or 'ok'}).",
                        )
                    else:
                        messages.info(
                            request,
                            f"RADIUS ответил: Access-Reject "
                            f"(code={r.code}). Соединение работает, "
                            f"но credentials не подошли.",
                        )
                    result = r

    # статистика
    radius_users = UserAuthSettings.objects.filter(
        auth_source=UserAuthSettings.Source.RADIUS,
    ).select_related("user")[:50]

    return render(request, "access/radius.html", {
        "result": result,
        "radius_users": radius_users,
    })


@require_roles("supervisor")
@require_http_methods(["POST"])
def user_set_auth_source(request: HttpRequest, user_id: int) -> HttpResponse:
    from django.contrib.auth import get_user_model

    from .models import UserAuthSettings

    if not is_supervisor(request.user):
        return HttpResponseForbidden("Только SUPERVISOR")

    User = get_user_model()
    try:
        target = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "Пользователь не найден.")
        return redirect(reverse("access:radius"))

    source = request.POST.get("source") or "local"
    if source not in {"local", "radius"}:
        messages.error(request, "Неверный auth_source.")
        return redirect(reverse("access:radius"))

    settings_obj, _ = UserAuthSettings.objects.get_or_create(user=target)
    settings_obj.auth_source = source
    settings_obj.save(update_fields=["auth_source", "updated_at"])

    log_auth_event(
        AuthAuditLog.Event.ROLE_GRANTED,     # переиспользуем; лучше добавить
                                               # отдельный AUTH_SOURCE_CHANGED
        user=request.user, target_user=target,
        ip=get_client_ip(request),
        detail={"auth_source": source},
    )
    messages.success(
        request,
        f"Источник аутентификации для {target.username}: {source}",
    )
    return redirect(reverse("access:radius"))


@require_roles("supervisor", "admin")
@require_http_methods(["GET"])
def break_glass_page(request):
    """Только просмотр. Управление — через manage.py с физического доступа."""
    from .models import BreakGlassAccount
    from .services import can_enable_break_glass

    account = BreakGlassAccount.get()

    can_enable = False
    can_enable_reason = "—"
    if account is not None and not account.is_currently_active():
        can_enable, can_enable_reason = can_enable_break_glass()

    return render(request, "access/break_glass.html", {
        "account": account,
        "currently_active": (
            account.is_currently_active() if account else False
        ),
        "can_enable": can_enable,
        "can_enable_reason": can_enable_reason,
    })


@require_roles("supervisor")
@require_http_methods(["GET", "POST"])
def access_review_page(request):
    from .models import AccessReviewItem, AccessReviewRun
    from .services import (
        confirm_review_item,
        revoke_review_item,
        start_access_review,
    )

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "start":
            run = start_access_review(
                triggered_by=request.user,
                notes=request.POST.get("notes", "")[:500],
            )
            messages.success(request, f"Review запущен: {run.id}")
            return redirect(reverse("access:access-review-detail",
                                     args=[run.id]))
        elif action in ("confirm", "revoke"):
            try:
                item = AccessReviewItem.objects.get(pk=request.POST["item_id"])
                comment = request.POST.get("comment", "")[:255]
                if action == "confirm":
                    confirm_review_item(item, by_user=request.user,
                                         comment=comment)
                else:
                    revoke_review_item(item, by_user=request.user,
                                        comment=comment)
                messages.success(request, "Обработано.")
            except Exception as exc:
                messages.error(request, str(exc))
            return redirect(request.path)

    runs = AccessReviewRun.objects.all()[:20]
    return render(request, "access/access_review.html", {"runs": runs})


@require_roles("supervisor")
def access_review_detail(request, run_id):
    from django.shortcuts import get_object_or_404

    from .models import AccessReviewRun

    run = get_object_or_404(AccessReviewRun, pk=run_id)
    items = run.items.select_related(
        "assignment", "assignment__user",
    ).order_by("status", "-created_at")
    return render(request, "access/access_review_detail.html", {
        "run": run, "items": items,
    })


@require_roles("supervisor")
@require_http_methods(["GET"])
def service_accounts_list(request):
    from .models import ServiceAccount

    accounts = ServiceAccount.objects.select_related("domain", "created_by")
    return render(request, "access/service_accounts_list.html", {
        "accounts": accounts,
    })


@require_roles("supervisor")
@require_http_methods(["GET", "POST"])
def service_account_create(request):
    from django.contrib import messages

    from .models import ServiceAccount, ServiceAccountToken

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        description = (request.POST.get("description") or "").strip()
        scope = request.POST.get("scope") or ""
        domain_id = request.POST.get("domain") or None
        ttl_days = request.POST.get("ttl_days") or "365"

        try:
            domain = None
            if domain_id:
                from apps.inventory.models import Domain
                domain = Domain.objects.get(pk=int(domain_id))

            acc = ServiceAccount(
                name=name, description=description,
                scope=scope, domain=domain,
                created_by=request.user,
            )
            acc.full_clean()
            acc.save()

            expires_at = None
            try:
                days = int(ttl_days)
                if days > 0:
                    expires_at = timezone.now() + timezone.timedelta(days=days)
            except ValueError:
                pass

            token, plaintext = ServiceAccountToken.issue(
                account=acc,
                name="initial",
                created_by=request.user,
                expires_at=expires_at,
            )
            log_auth_event(
                AuthAuditLog.Event.SERVICE_TOKEN_ISSUED,
                user=request.user, ip=get_client_ip(request),
                detail={
                    "account": acc.name,
                    "token_prefix": token.token_prefix,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
            )
            messages.success(
                request,
                "Сервисный аккаунт создан. Скопируйте токен — "
                "он показан только один раз!",
            )
            return render(request, "access/service_account_token.html", {
                "account": acc, "plaintext": plaintext,
            })
        except Exception as exc:
            messages.error(request, f"Ошибка: {exc}")

    from apps.inventory.models import Domain
    return render(request, "access/service_account_create.html", {
        "domains": Domain.objects.all(),
        "scopes": ServiceAccount.Scope.choices,
    })


@require_roles("supervisor")
@require_http_methods(["POST"])
def service_account_revoke(request, pk):
    from .models import ServiceAccount

    acc = get_object_or_404(ServiceAccount, pk=pk)
    acc.is_active = False
    acc.save(update_fields=["is_active"])

    log_auth_event(
        AuthAuditLog.Event.SERVICE_TOKEN_REVOKED,
        user=request.user, ip=get_client_ip(request),
        detail={"account": acc.name},
    )
    messages.success(request, f"Аккаунт {acc.name} отключён.")
    return redirect(reverse("access:service-accounts-list"))


@require_roles("supervisor")
@require_http_methods(["POST"])
def service_token_issue(request, account_id):
    from django.contrib import messages

    from .models import ServiceAccount, ServiceAccountToken

    acc = get_object_or_404(ServiceAccount, pk=account_id)
    name = (request.POST.get("name") or "").strip()
    ttl_days = request.POST.get("ttl_days") or "365"

    expires_at = None
    try:
        days = int(ttl_days)
        if days > 0:
            expires_at = timezone.now() + timezone.timedelta(days=days)
    except ValueError:
        pass

    token, plaintext = ServiceAccountToken.issue(
        account=acc, name=name or "additional",
        created_by=request.user, expires_at=expires_at,
    )
    log_auth_event(
        AuthAuditLog.Event.SERVICE_TOKEN_ISSUED,
        user=request.user, ip=get_client_ip(request),
        detail={
            "account": acc.name, "token_prefix": token.token_prefix,
        },
    )
    return render(request, "access/service_account_token.html", {
        "account": acc, "plaintext": plaintext,
    })


@require_roles("supervisor")
@require_http_methods(["POST"])
def service_token_revoke(request, account_id, token_id):
    from .models import ServiceAccount, ServiceAccountToken

    acc = get_object_or_404(ServiceAccount, pk=account_id)
    token = get_object_or_404(ServiceAccountToken, pk=token_id, account=acc)

    token.revoked_at = timezone.now()
    token.revoked_by = request.user
    token.revoked_reason = (request.POST.get("reason") or "")[:255]
    token.save(update_fields=["revoked_at", "revoked_by", "revoked_reason"])

    log_auth_event(
        AuthAuditLog.Event.SERVICE_TOKEN_REVOKED,
        user=request.user, ip=get_client_ip(request),
        detail={"account": acc.name, "token_prefix": token.token_prefix},
    )
    messages.success(request, "Токен отозван.")
    return redirect(reverse("access:service-account-detail", args=[acc.pk]))


@require_roles("supervisor")
@require_http_methods(["GET"])
def service_account_detail(request, pk):
    from .models import ServiceAccount

    acc = get_object_or_404(ServiceAccount, pk=pk)
    return render(request, "access/service_account_detail.html", {
        "account": acc,
        "tokens": acc.tokens.all(),
    })


# --- IP access list ---

@require_roles("supervisor")
@require_http_methods(["GET", "POST"])
def ip_rules_page(request):
    from django.contrib import messages

    from .models import IPAllowlistRule

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "add":
            try:
                scope = request.POST.get("scope")
                cidr = (request.POST.get("cidr") or "").strip()
                description = (request.POST.get("description") or "")[:255]
                role = (request.POST.get("role") or "").strip()
                user_id = request.POST.get("user") or None

                rule = IPAllowlistRule(
                    scope=scope, cidr=cidr,
                    description=description, role=role or "",
                    created_by=request.user,
                )
                if user_id:
                    from django.contrib.auth import get_user_model
                    
                    User = get_user_model()
                    rule.user = User.objects.get(pk=int(user_id))
                rule.full_clean()
                rule.save()
                messages.success(request, f"Правило добавлено: {rule}")
            except Exception as exc:
                messages.error(request, f"Ошибка: {exc}")
        elif action == "delete":
            rule_id = request.POST.get("rule_id")
            IPAllowlistRule.objects.filter(pk=rule_id).delete()
            messages.success(request, "Правило удалено.")
        return redirect(reverse("access:ip-rules"))

    rules = IPAllowlistRule.objects.select_related("user").order_by("scope", "cidr")

    from django.contrib.auth import get_user_model

    User = get_user_model()

    return render(request, "access/ip_rules.html", {
        "rules": rules,
        "scopes": IPAllowlistRule.Scope.choices,
        "roles": [(r.value, r.value) for r in _all_role_values()],
        "users": User.objects.filter(is_active=True).order_by("username"),
    })


def _all_role_values():
    from .roles import Role
    return list(Role)

