from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .services import (
    active_deployments,
    collect_metrics,
    deployment_trend,
    domains_overview,
    recent_deployments,
)


@login_required
def dashboard_view(request):
    user = request.user
    return render(request, "dashboard/index.html", {
        "metrics": collect_metrics(user),
        "recent": recent_deployments(user),
        "active": active_deployments(user),
        "trend": deployment_trend(user),
        "domains": domains_overview(user),
    })


@login_required
def metrics_partial(request):
    return render(request, "dashboard/_metrics.html", {
        "metrics": collect_metrics(request.user),
    })


@login_required
def recent_partial(request):
    return render(request, "dashboard/_deployments.html", {
        "recent": recent_deployments(request.user),
    })


@login_required
def active_partial(request):
    return render(request, "dashboard/_active.html", {
        "active": active_deployments(request.user),
    })