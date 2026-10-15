from __future__ import annotations

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_http_methods
from loguru import logger

from apps.core.utils import get_client_ip

from .models import SecretAccessLog, log_action
from .runtime import SecretsSealed, runtime
from .transport_guard import (
    InsecureTransport,
    enforce_secure_unseal,
    inspect_transport,
    is_secure_for_unseal,
)


@staff_member_required
@require_http_methods(["POST"])
def grant_create(request: HttpRequest, path: str) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    from django.contrib.auth import get_user_model

    from .models import SecretAccessGrant
    from .services import get_ref, grant_access

    User = get_user_model()
    ref = get_ref(path, "value")
    if ref is None:
        messages.error(request, "Секрет не найден.")
        return redirect(reverse("secrets:items"))

    username = (request.POST.get("username") or "").strip()
    reason = (request.POST.get("reason") or "").strip()

    try:
        to_user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, f"Пользователь {username!r} не найден.")
        return redirect(reverse("secrets:item-edit", args=[path]))

    try:
        grant_access(ref, to_user, by_user=request.user,
                     reason=reason, ip=get_client_ip(request))
        messages.success(request, f"Грант выдан {username}.")
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))

    return redirect(reverse("secrets:item-edit", args=[path]))


@staff_member_required
@require_http_methods(["POST"])
def grant_revoke(request: HttpRequest, path: str, grant_id: int) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    from .models import SecretAccessGrant
    from .services import revoke_grant

    try:
        grant = SecretAccessGrant.objects.get(pk=grant_id)
    except SecretAccessGrant.DoesNotExist:
        messages.error(request, "Грант не найден.")
        return redirect(reverse("secrets:item-edit", args=[path]))

    try:
        revoke_grant(grant, by_user=request.user,
                     ip=get_client_ip(request))
        messages.success(request, "Грант отозван.")
    except PermissionError as exc:
        messages.error(request, str(exc))

    return redirect(reverse("secrets:item-edit", args=[path]))


@staff_member_required
@require_http_methods(["POST"])
def transfer_initiate(request: HttpRequest, path: str) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    from django.contrib.auth import get_user_model

    from .services import get_ref, initiate_transfer

    User = get_user_model()
    ref = get_ref(path, "value")
    if ref is None:
        messages.error(request, "Секрет не найден.")
        return redirect(reverse("secrets:items"))

    username = (request.POST.get("username") or "").strip()
    reason = (request.POST.get("reason") or "").strip()

    try:
        to_user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, f"Пользователь {username!r} не найден.")
        return redirect(reverse("secrets:item-edit", args=[path]))

    try:
        transfer = initiate_transfer(ref, to_user,
                                     by_user=request.user, reason=reason)
        messages.success(
            request,
            f"Передача владения инициирована (ID: {transfer.id}). "
            "Требует подтверждения другого SUPERVISOR'а.",
        )
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))

    return redirect(reverse("secrets:item-edit", args=[path]))


@staff_member_required
@require_http_methods(["POST"])
def transfer_approve(request: HttpRequest, transfer_id) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    from .models import SecretOwnershipTransfer
    from .services import approve_transfer

    try:
        transfer = SecretOwnershipTransfer.objects.get(pk=transfer_id)
    except SecretOwnershipTransfer.DoesNotExist:
        messages.error(request, "Передача не найдена.")
        return redirect(reverse("secrets:items"))

    try:
        approve_transfer(transfer, by_user=request.user,
                         ip=get_client_ip(request))
        messages.success(request, "Передача подтверждена.")
    except (PermissionError, ValueError) as exc:
        messages.error(request, str(exc))

    return redirect(reverse("secrets:item-edit", args=[transfer.ref.path]))


@require_http_methods(["GET", "POST"])
@staff_member_required
def unlock_view(request):
    status = runtime.status()
    if status.state == "unsealed":
        return redirect("/admin/")
    if status.state == "uninitialized":
        return redirect(reverse("admin:index"))

    # --- Проверка транспорта ---
    transport_ok, reason, info = is_secure_for_unseal(request)

    if request.method == "POST":
        if not transport_ok:
            logger.warning(
                f"secrets: unlock rejected — insecure transport "
                f"({reason}, ip={info.client_ip}, "
                f"scheme={info.scheme}, tls={info.tls_version or '-'})"
            )
            log_action(
                SecretAccessLog.Action.UNLOCK,
                user=request.user, ip=info.client_ip,
                success=False,
                error=f"insecure_transport:{reason}",
                detail={
                    "scheme": info.scheme,
                    "tls": info.tls_version,
                    "source": info.source,
                    "trusted_proxy": info.trusted_proxy,
                },
            )
            # Не даём ввести ключ даже если пользователь уже отправил форму
            messages.error(
                request,
                "Мастер-ключ нельзя вводить по небезопасному соединению. "
                "См. справку на странице.",
            )
            return render(request, "secrets/unlock.html", {
                "transport": info,
                "transport_ok": False,
                "transport_reason": reason,
            })

        key = request.POST.get("master_key", "").strip()
        if not key:
            messages.error(request, "Введите мастер-ключ.")
        else:
            try:
                runtime.unlock(key)
                log_action(
                    SecretAccessLog.Action.UNLOCK,
                    user=request.user, ip=info.client_ip,
                    success=True,
                    detail={"pid": status.pid, "tls": info.tls_version},
                )
                logger.info(
                    f"secrets: unlocked via UI by {request.user.username} "
                    f"(tls={info.tls_version or 'n/a'})"
                )
                return redirect("/admin/")
            except SecretsSealed as exc:
                log_action(
                    SecretAccessLog.Action.UNLOCK,
                    user=request.user, ip=info.client_ip,
                    success=False, error=str(exc),
                )
                messages.error(request, f"Не удалось: {exc}")

    return render(request, "secrets/unlock.html", {
        "transport": info,
        "transport_ok": transport_ok,
        "transport_reason": reason,
    })


@require_GET
def health(request):
    secrets_status = runtime.status()
    payload = {
        "status": "ok" if secrets_status.state == "unsealed" else "degraded",
        "version": "0.1.0",
        "secrets": {
            "state": secrets_status.state,
            "active_backend": secrets_status.active_backend or None,
        },
    }
    http_status = 200 if secrets_status.state == "unsealed" else 503
    return JsonResponse(payload, status=http_status)