"""UI управления backend и credentials."""
from __future__ import annotations

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from loguru import logger

from apps.access.decorators import require_aal_action, require_roles
from apps.core.decorators import rate_limit
from apps.core.permissions import is_supervisor
from apps.core.utils import get_client_ip

from .backends import BACKEND_CLASSES, get_backend, is_registered
from .forms import SecretCreateForm, SecretEditForm
from .models import SecretAccessLog, log_action
from .runtime import SecretsSealed, runtime
from .services import (
    delete_backend_credentials,
    delete_secret,
    get_active_backend,
    get_backend_credentials,
    get_record,
    list_backends,
    list_records,
    record_exists,
    set_active_backend,
    set_backend_credentials,
    set_secret,
    test_backend,
)


def _require_unsealed(request) -> None:
    if not runtime.is_unsealed():
        raise SecretsSealed("runtime sealed")


def _backend_form_fields(name: str) -> list[dict]:
    """Описание полей формы для backend.

    Если у класса есть classmethod required_credentials — используем его.
    Иначе — дефолт (url, token, mount).
    """
    cls = BACKEND_CLASSES.get(name)
    if cls and hasattr(cls, "required_credentials"):
        try:
            return cls.required_credentials()
        except Exception:
            pass
    return [
        {"key": "url", "label": "URL", "required": True},
        {"key": "token", "label": "Token", "required": True, "secret": True},
    ]


# @staff_member_required
@require_roles("supervisor")
@require_aal_action("secrets.backend.change")
@require_http_methods(["GET"])
def backend_page(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        messages.error(request, "Секреты заблокированы. Сначала разблокируйте.")
        return redirect("/admin/")

    backends = list_backends()
    for b in backends:
        cached = get_cached_health(b.name)
        if cached and b.active:
            # cached имеет приоритет над только что полученным
            b.health = cached
    active = get_active_backend()

    # поле для редактирования — по запросу ?edit=<name>
    edit_name = request.GET.get("edit", "") or active
    creds = get_backend_credentials(edit_name)
    fields = _backend_form_fields(edit_name)

    # маскируем секретные поля
    for f in fields:
        if f.get("secret") and creds.get(f["key"]):
            f["value_masked"] = "••••••••"
        else:
            f["value"] = creds.get(f["key"], "")

    is_openbao = (edit_name == "openbao")

    return render(request, "secrets/backend.html", {
        "backends": backends,
        "active": active,
        "edit_name": edit_name,
        "fields": fields,
        "has_creds": bool(creds),
        "is_openbao": is_openbao,
    })


# @staff_member_required
@require_roles("supervisor")
@rate_limit(limit=10, window=3600, key_prefix="secrets_backend_change")
@require_aal_action("secrets.backend.change")
@require_http_methods(["POST"])
def backend_set(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    name = request.POST.get("name", "")
    if not is_registered(name):
        messages.error(request, f"Неизвестный backend: {name}")
        return redirect("/admin/secrets/backend/")

    ok = set_active_backend(name, user=request.user, ip=get_client_ip(request))
    if ok:
        messages.success(request, f"Активный backend: {name}")
    else:
        messages.error(
            request,
            f"Не удалось переключиться на {name} — health-check не прошёл. "
            "Проверьте credentials.",
        )
    return redirect("/admin/secrets/backend/")


# @staff_member_required
@require_roles("supervisor")
@rate_limit(limit=10, window=3600, key_prefix="secrets_backend_change")
@require_aal_action("secrets.backend.change")
@require_http_methods(["POST"])
def backend_credentials_save(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    name = request.POST.get("name", "")
    if not is_registered(name):
        messages.error(request, f"Неизвестный backend: {name}")
        return redirect("/admin/secrets/backend/")

    fields = _backend_form_fields(name)
    values: dict[str, str] = {}
    for f in fields:
        key = f["key"]
        raw = request.POST.get(key, "").strip()
        # Секретные поля: пустое значение = "не менять"; явное "•••" = "не менять"
        if f.get("secret") and (not raw or raw == "••••••••"):
            continue
        if not raw:
            if f.get("required") and not get_backend_credentials(name).get(key):
                messages.error(request, f"Поле «{f['label']}» обязательно.")
                return redirect(f"/admin/secrets/backend/?edit={name}")
            continue
        values[key] = raw

    if not values:
        messages.info(request, "Нет изменений.")
        return redirect(f"/admin/secrets/backend/?edit={name}")

    set_backend_credentials(name, values, user=request.user,
                            ip=get_client_ip(request))

    # health-check после сохранения
    health = test_backend(name)
    if health.get("status") == "ok":
        messages.success(request, f"{name}: credentials сохранены, health OK.")
    else:
        messages.warning(
            request,
            f"{name}: credentials сохранены, но health вернул "
            f"{health.get('status')} — {health.get('detail', '')}",
        )

    logger.info(f"secrets: credentials updated for {name} by {request.user.username}")
    return redirect(f"/admin/secrets/backend/?edit={name}")


# @staff_member_required
@require_roles("supervisor")
@require_aal_action("secrets.backend.change")
@require_http_methods(["POST"])
def backend_credentials_clear(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    name = request.POST.get("name", "")
    if not is_registered(name):
        return redirect("/admin/secrets/backend/")

    delete_backend_credentials(name, user=request.user, ip=get_client_ip(request))
    messages.success(request, f"{name}: credentials очищены.")
    return redirect("/admin/secrets/backend/")


# @staff_member_required
@require_roles("supervisor")
@require_http_methods(["POST"])
def backend_test(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    name = request.POST.get("name", "")
    result = test_backend(name)
    if result.get("status") == "ok":
        messages.success(request, f"{name}: OK ({result})")
    else:
        messages.error(request, f"{name}: {result}")
    return redirect(f"/admin/secrets/backend/?edit={name}")


# @staff_member_required
@require_roles("supervisor")
# @require_aal_action("secrets.backend.change")
@require_http_methods(["GET"])
def migrations_page(request):
    from .models import SecretsMigration
    rows = SecretsMigration.objects.order_by("-started_at")[:100]
    return render(request, "secrets/migrations.html", {
        "rows": rows,
    })



# ============================================================
#  Прикладные секреты
# ============================================================

# @staff_member_required
@login_required
# @require_roles("supervisor", "admin", "operator", "auditor", "viewer")
@require_aal_action("secrets.read")
def items_list(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        messages.error(request, "Секреты заблокированы.")
        return redirect("/admin/")

    from .services import list_refs_for_user

    q = (request.GET.get("q") or "").strip()
    scope = request.GET.get("scope", "mine")   # mine | granted | all

    user = request.user
    _is_supervisor = is_supervisor(user)

    if scope == "all" and _is_supervisor:
        refs = list_refs_for_user(user)
        readonly_mode = True
    else:
        refs = list_refs_for_user(user)
        readonly_mode = False

    if q:
        refs = [r for r in refs if q.lower() in r.path.lower()
                or q.lower() in r.display_name.lower()]

    rows = [
        {
            "ref": ref,
            "path": ref.path,
            "key": ref.key,
            "display_name": ref.display_name,
            "owner": ref.owner,
            "is_mine": ref.owner_id == user.pk,
            "last_accessed_at": ref.last_accessed_at,
            "access_count": ref.access_count,
        }
        for ref in refs
    ]

    return render(request, "secrets/items.html", {
        "rows": rows, "q": q, "scope": scope,
        "is_supervisor": _is_supervisor,
        "readonly_mode": readonly_mode,
    })


# @staff_member_required
@login_required
@require_aal_action("secrets.write")
@require_http_methods(["GET", "POST"])
def item_new(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    form = SecretCreateForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        path = form.cleaned_data["path"]
        key = form.cleaned_data["key"]
        value = form.cleaned_data["value"]

        if record_exists(path):
            messages.error(
                request,
                f"Запись {path!r} уже существует. "
                "Откройте её для редактирования."
            )
        else:
            ok = set_secret(path, key, value, user=request.user,
                            ip=get_client_ip(request))
            if ok:
                messages.success(request, f"Запись {path} создана.")
                return redirect(reverse("secrets:item-edit", args=[path]))
            messages.error(request, "Не удалось сохранить.")

    return render(request, "secrets/item_form.html", {
        "mode": "create", "form": form,
    })


# @staff_member_required\
@login_required
@require_aal_action("secrets.read")
@require_http_methods(["GET", "POST"])
def item_edit(request: HttpRequest, path: str) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    from .services import can_user_read, can_user_write, get_ref

    ref = get_ref(path, "value")
    if ref is None:
        messages.error(request, f"Запись {path!r} не найдена.")
        return redirect(reverse("secrets:items"))

    user = request.user
    _is_supervisor = is_supervisor(user)
    can_read = can_user_read(user, ref)
    can_write = can_user_write(user, ref)

    # SUPERVISOR без owner-прав — read-only метаданные
    if not can_read and not _is_supervisor:
        return HttpResponseForbidden("Нет доступа к этому секрету")

    existing = get_record(path) if can_read else {}

    form = SecretEditForm(request.POST or None, existing=existing)

    if request.method == "POST" and form.is_valid():
        if not can_write:
            messages.error(
                request,
                "Изменять секрет может только владелец.",
            )
            return redirect(reverse("secrets:item-edit", args=[path]))

        changed = 0
        for k, v in form.updates().items():
            if set_secret(path, k, v, user=user, ip=get_client_ip(request)):
                changed += 1

        ne = form.new_entry()
        if ne:
            k, v = ne
            if set_secret(path, k, v, user=user, ip=get_client_ip(request)):
                changed += 1

        if changed:
            messages.success(request, f"Изменено ключей: {changed}.")
            return redirect(reverse("secrets:item-edit", args=[path]))
        messages.info(request, "Нет изменений.")

    return render(request, "secrets/item_form.html", {
        "mode": "edit",
        "form": form,
        "path": path,
        "existing": existing,
        "ref": ref,
        "can_read": can_read,
        "can_write": can_write,
        "is_supervisor": _is_supervisor,
    })


@login_required
@require_aal_action("secrets.write")
@require_http_methods(["POST"])
def item_delete(request: HttpRequest, path: str) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    if not record_exists(path):
        messages.warning(request, f"Запись {path!r} не найдена.")
        return redirect(reverse("secrets:items"))

    ok = delete_secret(path, user=request.user, ip=get_client_ip(request))
    if ok:
        messages.success(request, f"Запись {path} удалена.")
    else:
        messages.error(request, "Не удалось удалить.")
    return redirect(reverse("secrets:items"))


@login_required
@require_aal_action("secrets.write")
@require_http_methods(["POST"])
def item_key_delete(request: HttpRequest, path: str, key: str) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    # у нас нет отдельного API для удаления ключа — используем backend
    try:
        b = get_backend()
        existing = get_record(path)
        if key not in existing:
            messages.warning(request, f"Ключ {key!r} не найден.")
            return redirect(reverse("secrets:item-edit", args=[path]))

        # читаем всё, кроме ключа
        remaining = {k: v for k, v in existing.items() if k != key}
        b.delete(path)
        for k, v in remaining.items():
            b.set(path, k, v)

        log_action(
            SecretAccessLog.Action.DELETE, path=path, key=key,
            user=request.user, ip=get_client_ip(request), success=True,
        )
        messages.success(request, f"Ключ {key!r} удалён.")
    except Exception as exc:
        logger.error(f"secrets: delete key {path}:{key}: {exc}")
        messages.error(request, f"Ошибка: {exc}")

    return redirect(reverse("secrets:item-edit", args=[path]))


# ============================================================
#  Renew токена OpenBao (кнопка вручную)
# ============================================================

# @staff_member_required
@require_roles("supervisor")
@rate_limit(limit=5, window=3600, key_prefix="secrets_backend_change")
@require_aal_action("secrets.backend.change")
@require_http_methods(["POST"])
def renew_openbao_now(request: HttpRequest) -> HttpResponse:
    if not runtime.is_unsealed():
        return HttpResponseForbidden("sealed")

    from .tasks import renew_openbao_token_now

    result = renew_openbao_token_now()
    if result.get("status") == "ok":
        messages.success(
            request,
            f"Токен обновлён. Новый TTL: {result.get('ttl', '?')}с.",
        )
    elif result.get("status") == "skipped":
        messages.info(request, f"Пропущено: {result.get('reason')}")
    else:
        messages.error(
            request,
            f"Не удалось: {result.get('detail', 'unknown')}",
        )
    return redirect(f"/admin/secrets/backend/?edit=openbao")


# ============================================================
#  Периодический health (по запросу страницы backend)
# ============================================================

def get_cached_health(name: str) -> dict:
    """Читает кэш health-статуса, если есть."""
    from django.core.cache import cache
    
    return cache.get(f"secrets:health:{name}", {}) or {}