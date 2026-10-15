from __future__ import annotations

from django.contrib.auth.models import AnonymousUser

from apps.inventory.models import Host

from .models import Deployment

ACTIVE_STATUSES = (
    Deployment.Status.PENDING,
    Deployment.Status.DISPATCHED,
    Deployment.Status.RUNNING,
)

FINAL_STATUSES = (
    Deployment.Status.SUCCESS,
    Deployment.Status.PARTIAL,
    Deployment.Status.FAILED,
    Deployment.Status.CANCELLED,
    Deployment.Status.EXPIRED,
)


def can_deploy_host(user, host: Host) -> bool:
    if isinstance(user, AnonymousUser) or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return user.has_perm("inventory.deploy_host", host)


def can_view_host(user, host: Host) -> bool:
    if isinstance(user, AnonymousUser) or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return (
        user.has_perm("inventory.view_host", host)
        or user.has_perm("inventory.view_deployments", host)
    )


def can_view_deployment(user, deployment: Deployment) -> bool:
    return can_view_host(user, deployment.host)


def is_active(deployment: Deployment) -> bool:
    return deployment.status in ACTIVE_STATUSES


def is_final(deployment: Deployment) -> bool:
    return deployment.status in FINAL_STATUSES


def can_view_bulk(user, bulk) -> bool:
    if isinstance(user, AnonymousUser) or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    
    from guardian.shortcuts import get_objects_for_user

    from apps.inventory.models import Host

    visible = get_objects_for_user(
        user, "inventory.view_host", Host.objects.all(),
    )
    return bulk.deployments.filter(host__in=visible).exists()