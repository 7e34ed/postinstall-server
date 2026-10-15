from __future__ import annotations

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django_filters.views import FilterView
from django_tables2.views import SingleTableMixin
from guardian.shortcuts import get_objects_for_user

from apps.access.decorators import require_aal_action
from apps.access.permissions import user_can_deploy
from apps.deploy.models import BulkDeployment
from apps.deploy.perms import can_view_bulk
from apps.deploy.services import bulk_create_deployments, cancel_bulk, update_host_state
from apps.inventory.models import Host

from .filters import DeploymentFilter
from .models import Deployment
from .perms import (
    can_deploy_host,
    can_view_deployment,
    is_active,
    is_final,
)
from .services import active_deployment_for, create_deployment
from .tables import DeploymentTable


class DeploymentListView(SingleTableMixin, FilterView):
    model = Deployment
    table_class = DeploymentTable
    filterset_class = DeploymentFilter
    template_name = "deploy/deployment_list.html"
    paginate_by = 50

    def get_queryset(self):
        qs = (
            super().get_queryset()
            .select_related("host", "host__domain", "host__host_set")
        )
        user = self.request.user
        if not user.is_authenticated:
            return qs.none()
        if user.is_superuser:
            return qs
        # фильтруем по view_host на уровне хоста
        visible_hosts = get_objects_for_user(
            user, "inventory.view_host", Host.objects.all(),
        )
        return qs.filter(host__in=visible_hosts)


def deployment_detail_view(request, pk):
    deployment = get_object_or_404(
        Deployment.objects.select_related("host", "host__domain", "host__host_set"),
        pk=pk,
    )
    if not can_view_deployment(request.user, deployment):
        return HttpResponseForbidden("Нет доступа к этому развёртыванию")

    can_cancel = is_active(deployment) and can_deploy_host(request.user, deployment.host)
    can_retry = is_final(deployment) and can_deploy_host(request.user, deployment.host)

    return render(request, "deploy/deployment_detail.html", {
        "deployment": deployment,
        "report": getattr(deployment, "report", None),
        "can_cancel": can_cancel,
        "can_retry": can_retry,
        "is_final": is_final(deployment),
    })


def deployment_status_view(request, pk):
    """HTMX endpoint: возвращает только блок статуса. Для polling."""
    deployment = get_object_or_404(Deployment, pk=pk)
    if not can_view_deployment(request.user, deployment):
        return HttpResponseForbidden()
    return render(request, "deploy/_status_block.html", {
        "deployment": deployment,
        "report": getattr(deployment, "report", None),
        "is_final": is_final(deployment),
    })

@require_aal_action("deploy.create")
@require_POST
def host_apply_view(request, host_id):
    host = get_object_or_404(Host, pk=host_id)
    if not user_can_deploy(request.user, host):
        return HttpResponseForbidden("Нет прав на деплой")

    try:
        deployment = create_deployment(host, user=request.user)
    except ValidationError as exc:
        messages.error(request, str(exc.message))
        if request.headers.get("HX-Request"):
            return HttpResponse(
                status=409,
                headers={"HX-Trigger": "showMessage"},
            )
        return redirect("inventory:host-detail", pk=host.pk)

    messages.success(
        request, f"Задача создана для {host.hostname}: {str(deployment.id)[:8]}"
    )
    if request.headers.get("HX-Request"):
        return HttpResponse(
            status=204,
            headers={"HX-Redirect": reverse("deploy:detail", args=[deployment.id])},
        )
    return redirect("deploy:detail", pk=deployment.id)


@require_POST
def deployment_cancel_view(request, pk):
    deployment = get_object_or_404(Deployment, pk=pk)
    if not can_deploy_host(request.user, deployment.host):
        return HttpResponseForbidden()

    if not is_active(deployment):
        messages.warning(request, "Задача уже завершена — отмена невозможна.")
    else:
        deployment.status = Deployment.Status.CANCELLED
        deployment.finished_at = timezone.now()
        deployment.save(update_fields=["status", "finished_at"])
        messages.success(request, "Задача отменена.")

    if request.headers.get("HX-Request"):
        return HttpResponse(status=204,
                            headers={"HX-Redirect": request.path})
    return redirect("deploy:detail", pk=deployment.id)


@require_POST
def deployment_retry_view(request, pk):
    old = get_object_or_404(Deployment, pk=pk)
    if not can_deploy_host(request.user, old.host):
        return HttpResponseForbidden()

    active = active_deployment_for(old.host)
    if active is not None:
        messages.warning(
            request,
            f"У хоста {old.host.hostname} уже есть активная задача "
            f"({str(active.id)[:8]}). Отмените её или дождитесь завершения.",
        )
        return redirect("deploy:detail", pk=old.id)

    new = create_deployment(old.host, user=request.user, priority=old.priority)
    messages.success(request, f"Новая задача: {str(new.id)[:8]}")

    if request.headers.get("HX-Request"):
        return HttpResponse(status=204,
                            headers={"HX-Redirect": reverse("deploy:detail", args=[new.id])})
    return redirect("deploy:detail", pk=new.id)


# ---------- Массовый деплой ----------

@require_aal_action("deploy.create")
@require_POST
def bulk_apply_view(request):
    host_ids = request.POST.getlist("host_ids")
    if not host_ids:
        messages.error(request, "Не выбрано ни одного хоста.")
        if request.headers.get("HX-Request"):
            return HttpResponse(status=400)
        return redirect("inventory:host-list")

    try:
        host_ids_int = [int(x) for x in host_ids]
    except ValueError:
        return HttpResponse(status=400)

    # фильтруем по правам
    from apps.inventory.models import Host
    hosts = Host.objects.filter(pk__in=host_ids_int)
    allowed_ids = [h.pk for h in hosts if can_deploy_host(request.user, h)]

    if not allowed_ids:
        messages.error(request, "Нет прав на деплой выбранных хостов.")
        if request.headers.get("HX-Request"):
            return HttpResponse(status=403)
        return redirect("inventory:host-list")

    result = bulk_create_deployments(allowed_ids, user=request.user)
    bulk = result["bulk"]

    parts = [f"создано: {len(result['created'])}"]
    if result["skipped"]:
        parts.append(f"пропущено: {len(result['skipped'])}")
    if result["errors"]:
        parts.append(f"ошибок: {len(result['errors'])}")
    messages.success(request, "Пакет запущен. " + ", ".join(parts))

    if request.headers.get("HX-Request"):
        return HttpResponse(
            status=204,
            headers={"HX-Redirect": reverse("deploy:bulk-detail", args=[bulk.id])},
        )
    return redirect("deploy:bulk-detail", pk=bulk.id)


def bulk_detail_view(request, pk):
    bulk = get_object_or_404(BulkDeployment, pk=pk)
    if not can_view_bulk(request.user, bulk):
        return HttpResponseForbidden()

    bulk.refresh_from_db()
    deployments = (
        bulk.deployments
        .select_related("host", "host__domain")
        .order_by("-created_at")
    )
    return render(request, "deploy/bulk_detail.html", {
        "bulk": bulk,
        "deployments": deployments,
        "is_final": bulk.is_final,
        "can_cancel": not bulk.is_final and can_deploy_host(
            request.user,
            bulk.deployments.first().host if bulk.deployments.exists() else None,
        ) if bulk.deployments.exists() else False,
    })


def bulk_status_partial(request, pk):
    bulk = get_object_or_404(BulkDeployment, pk=pk)
    if not can_view_bulk(request.user, bulk):
        return HttpResponseForbidden()
    bulk.refresh_from_db()
    return render(request, "deploy/_bulk_status.html", {
        "bulk": bulk,
        "is_final": bulk.is_final,
    })


@require_POST
def bulk_cancel_view(request, pk):
    bulk = get_object_or_404(BulkDeployment, pk=pk)
    if not can_view_bulk(request.user, bulk):
        return HttpResponseForbidden()

    count = cancel_bulk(bulk)
    messages.success(request, f"Отменено задач: {count}.")

    if request.headers.get("HX-Request"):
        return HttpResponse(status=204,
                            headers={"HX-Redirect": request.path})
    return redirect("deploy:bulk-detail", pk=bulk.id)


# ---------- Дрифт ----------

def drift_list_view(request):
    from django.db.models import Q
    from guardian.shortcuts import get_objects_for_user

    from apps.inventory.models import Host

    user = request.user
    if not user.is_authenticated:
        return HttpResponseForbidden()

    qs = Host.objects.filter(managed=True).select_related("domain", "host_set")
    if not user.is_superuser:
        qs = get_objects_for_user(user, "inventory.view_host", qs)

    drifted = qs.filter(drift_detected_at__isnull=False).order_by("-drift_detected_at")
    unsynced = qs.filter(
        last_deployed_config_hash="", agent__isnull=False,
    ).order_by("hostname")

    return render(request, "deploy/drift_list.html", {
        "drifted": drifted,
        "unsynced": unsynced,
    })


@require_POST
def drift_rescan_view(request, host_id: int):
    from apps.inventory.models import Host
    host = get_object_or_404(Host, pk=host_id)
    if not can_deploy_host(request.user, host):
        return HttpResponseForbidden()

    result = update_host_state(host)
    messages.success(
        request,
        f"{host.hostname}: {result['state']}",
    )
    if request.headers.get("HX-Request"):
        return HttpResponse(status=204,
                            headers={"HX-Redirect": reverse(
                                "inventory:host-detail", args=[host.pk],
                            )})
    return redirect("inventory:host-detail", pk=host.pk)


@require_POST
def drift_sync_all_view(request):
    """Синхронно создаёт bulk на все drift-хосты."""
    from django.db.models import Q
    from guardian.shortcuts import get_objects_for_user

    from apps.inventory.models import Host

    user = request.user
    qs = Host.objects.filter(managed=True, drift_detected_at__isnull=False)
    if not user.is_superuser:
        qs = get_objects_for_user(user, "inventory.view_host", qs)
        qs = qs.filter(pk__in=[
            h.pk for h in qs if can_deploy_host(user, h)
        ])

    host_ids = list(qs.values_list("id", flat=True))
    if not host_ids:
        messages.info(request, "Нет хостов с дрифтом.")
        return redirect("deploy:drift-list")

    result = bulk_create_deployments(
        host_ids, user=user,
        name=f"Синхронизация {timezone.now():%Y-%m-%d %H:%M}",
    )
    messages.success(
        request,
        f"Создано задач: {len(result['created'])} "
        f"(пропущено: {len(result['skipped'])}).",
    )
    return redirect("deploy:bulk-detail", pk=result["bulk"].id)