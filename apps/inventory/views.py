from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, render
from django_filters.views import FilterView
from django_tables2.views import SingleTableMixin
from guardian.shortcuts import get_objects_for_user

from apps.access.permissions import user_can_deploy, user_can_view_object
from apps.deploy.models import Deployment
from apps.deploy.services import active_deployment_for

from .filters import HostFilter
from .models import Host
from .tables import HostTable


class HostListView(SingleTableMixin, FilterView):
    model = Host
    table_class = HostTable
    filterset_class = HostFilter
    template_name = "inventory/host_list.html"
    paginate_by = 50

    def get_queryset(self):
        qs = super().get_queryset().select_related("domain", "host_set")
        user = self.request.user
        if not user.is_authenticated:
            return qs.none()
        if user.is_superuser:
            return qs
        # guardian: view_host на уровне объекта
        return get_objects_for_user(user, "inventory.view_host", qs)


def host_detail_view(request, pk):
    host = get_object_or_404(
        Host.objects.select_related("domain", "host_set"),
        pk=pk,
    )

    if not user_can_view_object(request.user, host):
        from django.core.exceptions import PermissionDenied

        raise PermissionDenied("Нет доступа к этому хосту")

    # Заменено на user_can_view_object
    # if not can_view_host(request.user, host):
    #     return HttpResponseForbidden("Нет доступа к этому хосту")

    deployments = (
        Deployment.objects
        .filter(host=host)
        .order_by("-created_at")[:20]
    )
    active = active_deployment_for(host)
    agent = getattr(host, "agent", None)

    return render(request, "inventory/host_detail.html", {
        "host": host,
        "agent": agent,
        "deployments": deployments,
        "active_deployment": active,
        "can_deploy": user_can_deploy(request.user, host),
        "resolved_settings": host.resolved_settings(),
        "resolved_hardening": host.resolved_hardening(),
    })