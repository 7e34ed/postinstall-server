"""UI для учётных данных."""
from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from django_filters.views import FilterView
from django_tables2.views import SingleTableMixin

from apps.access.decorators import require_aal_action, require_roles
from apps.access.permissions import active_roles, user_can_edit_object
from apps.access.roles import Role

from .filters import CredentialFilter
from .forms import CredentialForm
from .models import Credential
from .tables import CredentialTable


class CredentialListView(SingleTableMixin, FilterView):
    model = Credential
    table_class = CredentialTable
    filterset_class = CredentialFilter
    template_name = "credentials/credential_list.html"
    paginate_by = 50

    def get_queryset(self):
        qs = (
            super().get_queryset()
            .select_related("domain", "host_set", "host")
        )
        user = self.request.user
        if not user.is_authenticated:
            return qs.none()
        if user.is_superuser:
            return qs

        roles = active_roles(user)
        if not roles:
            return qs.none()

        # SUPERVISOR видит все метаданные (но не значения),
        # ADMIN — только в своём scope.
        if any(ra.role == Role.SUPERVISOR.value for ra in roles):
            return qs

        # ADMIN — фильтр по scope: объекты, которые покрыты хотя бы одной его ролью.
        # Используем условия OR по типам scope.
        from django.db.models import Q

        from apps.access.roles import ScopeType

        conditions = Q(pk__in=[])
        for ra in roles:
            if ra.role != Role.ADMIN.value:
                continue
            if ra.scope_type == ScopeType.DOMAIN.value:
                # credentials домена, host_set и host внутри домена
                conditions |= Q(domain_id=ra.scope_id)
                conditions |= Q(host_set__domain_id=ra.scope_id)
                conditions |= Q(host__domain_id=ra.scope_id)
            elif ra.scope_type == ScopeType.HOST_SET.value:
                conditions |= Q(host_set_id=ra.scope_id)
                conditions |= Q(host__host_set_id=ra.scope_id)
            elif ra.scope_type == ScopeType.HOST.value:
                conditions |= Q(host_id=ra.scope_id)
            elif ra.scope_type == ScopeType.GLOBAL.value:
                return qs

        return qs.filter(conditions).distinct()


@require_roles("supervisor", "admin")
@require_aal_action("credentials.change")
def credential_form_view(request, pk=None):
    instance = get_object_or_404(Credential, pk=pk) if pk else None

    if instance is not None and not user_can_edit_object(request.user, instance):
        raise PermissionDenied("Нет прав на редактирование этой записи")

    if request.method == "POST":
        form = CredentialForm(request.POST, instance=instance, user=request.user)
        if form.is_valid():
            cred = form.save()
            if request.headers.get("HX-Request"):
                return HttpResponse(
                    status=204,
                    headers={"HX-Redirect": reverse("credentials:list")},
                )
            return redirect("credentials:list")
    else:
        form = CredentialForm(instance=instance, user=request.user)

    return render(request, "credentials/credential_form.html", {
        "form": form,
        "instance": instance,
        "mode": "edit" if instance else "create",
    })


@require_POST
@require_roles("supervisor", "admin")
@require_aal_action("credentials.change")
def credential_delete_view(request, pk):
    cred = get_object_or_404(Credential, pk=pk)
    if not user_can_edit_object(request.user, cred):
        raise PermissionDenied("Нет прав на удаление этой записи")

    cred.delete()
    if request.headers.get("HX-Request"):
        return HttpResponse(status=200)
    return redirect("credentials:list")