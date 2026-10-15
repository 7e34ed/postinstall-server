"""UI LDAP-настроек и синхронизации."""
from __future__ import annotations

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from apps.access.decorators import require_roles
from apps.core.utils import get_client_ip
from apps.inventory.models import Domain

from .models import LDAPSyncRun
from .services import lookup_user, settings_for_domain, verify_user_active


@require_roles("supervisor")
@require_http_methods(["GET", "POST"])
def ldap_dashboard(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "test_user":
            email = (request.POST.get("email") or "").strip()
            domain_id = request.POST.get("domain")
            domain = Domain.objects.filter(pk=domain_id).first() if domain_id else None
            if not email or not domain:
                messages.error(request, "Укажите email и домен.")
            else:
                ok, why = verify_user_active(email, domain=domain)
                attrs = lookup_user(email, domain=domain) if ok else None
                messages.info(
                    request,
                    f"verify_user_active({email}) = {ok}: {why}"
                    + (f"; attrs={attrs}" if attrs else ""),
                )
        elif action == "sync_domain":
            domain_id = request.POST.get("domain")
            domain = Domain.objects.filter(pk=domain_id).first()
            if domain:
                from .tasks import sync_hosts_task
                run = LDAPSyncRun.objects.create(
                    domain=domain, kind=LDAPSyncRun.Kind.HOSTS,
                    triggered_by=request.user,
                )
                sync_hosts_task.delay(domain.pk, str(run.pk))
                messages.success(
                    request, f"Синк домена {domain.name} запущен (run {run.pk})."
                )
        return redirect(reverse("ldap:ldap-dashboard"))

    domains = Domain.objects.all()
    for d in domains:
        d._ldap_ok = settings_for_domain(d) is not None

    runs = LDAPSyncRun.objects.select_related("domain")[:50]

    return render(request, "ldap/dashboard.html", {
        "domains": domains,
        "runs": runs,
    })