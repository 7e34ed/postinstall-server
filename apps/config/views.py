from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from django_filters.views import FilterView
from django_tables2.views import SingleTableMixin
from guardian.shortcuts import get_objects_for_user

from apps.access.decorators import require_aal_action, require_roles
from apps.inventory.models import Host

from .filters import ProfileFilter
from .forms import ConfigProfileForm
from .models import ConfigProfile, ConfigRevision
from .services import resolve_for_host, resolve_hardening_for_host
from .tables import ProfileTable

# ---------- Список ----------

class ProfileListView(SingleTableMixin, FilterView, LoginRequiredMixin):
    model = ConfigProfile
    table_class = ProfileTable
    filterset_class = ProfileFilter
    template_name = "config/profile_list.html"
    paginate_by = 50

def get_queryset(self):
    qs = super().get_queryset()
    user = self.request.user
    
    if not user.is_authenticated:
        return qs.none()

    if user.is_superuser:
        return qs
    
    from apps.access.permissions import active_roles
    
    if not active_roles(user):
        return qs.none()
    return qs


# ---------- Создать / редактировать ----------

@require_roles("supervisor", "admin")
@require_aal_action("config.profile.change")
def profile_form_view(request, slug: str | None = None):
    from apps.access.permissions import user_can_edit_object

    instance = get_object_or_404(ConfigProfile, slug=slug) if slug else None

    if not user_can_edit_object(request.user, instance):
        from django.core.exceptions import PermissionDenied

        raise PermissionDenied("Нет прав на редактирование профиля")

    if request.method == "POST":
        form = ConfigProfileForm(request.POST, instance=instance)
        if form.is_valid():
            changed = form.has_changed()
            obj = form.save()

            # bump version, если что-то поменялось (для существующего профиля)
            if instance is not None and changed:
                obj.version = instance.version + 1
                obj.save(update_fields=["version"])
                ConfigRevision.objects.get_or_create(
                    profile=obj, version=obj.version,
                    defaults={"snapshot": obj.to_snapshot()},
                )

            if request.headers.get("HX-Request"):
                return HttpResponse(
                    status=204,
                    headers={"HX-Redirect": reverse(
                        "config:profile-edit", args=[obj.slug],
                    )},
                )
            return redirect("config:profile-edit", slug=obj.slug)
    else:
        form = ConfigProfileForm(instance=instance)

    # хосты, к которым применён этот профиль (для предпросмотра)
    preview_hosts = []
    
    if instance is not None:
        from django.db.models import Q

        preview_hosts = (
            Host.objects
            .filter(
                Q(host_set__profile_links__profile=instance)
                | Q(extra_profile_links__profile=instance)
            )
            .distinct()
            .select_related("domain", "host_set")
            .order_by("hostname")[:500]
        )

    return render(request, "config/profile_form.html", {
        "form": form,
        "instance": instance,
        "mode": "edit" if instance else "create",
        "preview_hosts": preview_hosts,
        "can_preview": instance is not None and len(preview_hosts) > 0,
    })


# ---------- Предпросмотр ----------

def profile_preview_view(request, slug: str):
    profile = get_object_or_404(ConfigProfile, slug=slug)
    host_id = request.GET.get("host")
    if not host_id:
        return render(request, "config/_preview_result.html", {
            "empty": True,
            "message": "Выберите хост для предпросмотра",
        })

    host = get_object_or_404(Host, pk=host_id)
    settings = resolve_for_host(host)
    hardening = resolve_hardening_for_host(host)

    return render(request, "config/_preview_result.html", {
        "empty": False,
        "host": host,
        "settings": settings,
        "hardening": hardening,
        "profile": profile,
    })


# ---------- Удалить ----------

@require_roles("supervisor", "admin")
@require_aal_action("config.profile.change")
@require_POST
def profile_delete_view(request, slug: str):
    profile = get_object_or_404(ConfigProfile, slug=slug)
    profile.delete()
    if request.headers.get("HX-Request"):
        return HttpResponse(status=200)
    return redirect("config:profile-list")