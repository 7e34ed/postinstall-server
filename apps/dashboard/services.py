"""Агрегации для дашборда.

Все запросы — read-only, фильтруются по scope пользователя
через apps.dashboard.scope.
"""
from __future__ import annotations

from datetime import timedelta

from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from apps.deploy.models import Agent, Deployment
from apps.inventory.models import Domain, Host

from .scope import agent_scope_q, deployment_scope_q, domain_scope_q, host_scope_q

ONLINE_THRESHOLD = timedelta(minutes=5)
RECENT_DEPLOYMENTS_LIMIT = 15
TREND_DAYS = 7


def collect_metrics(user) -> dict:
    now = timezone.now()
    online_cutoff = now - ONLINE_THRESHOLD
    day_ago = now - timedelta(hours=24)

    hosts_q = host_scope_q(user)
    depl_q = deployment_scope_q(user)
    agents_q = agent_scope_q(user)

    hosts_total = Host.objects.filter(hosts_q).count()
    hosts_managed = Host.objects.filter(hosts_q, managed=True).count()

    agents = Agent.objects.filter(agents_q, is_active=True)
    agents_total = agents.count()
    agents_online = agents.filter(last_seen_at__gte=online_cutoff).count()
    agents_offline = agents_total - agents_online

    hosts_no_agent = Host.objects.filter(
        hosts_q, managed=True, agent__isnull=True,
    ).count()

    active_statuses = [
        Deployment.Status.PENDING,
        Deployment.Status.DISPATCHED,
        Deployment.Status.RUNNING,
    ]
    active_total = Deployment.objects.filter(
        depl_q, status__in=active_statuses,
    ).count()

    last_24h = Deployment.objects.filter(depl_q, created_at__gte=day_ago)
    last_24h_total = last_24h.count()
    last_24h_success = last_24h.filter(status=Deployment.Status.SUCCESS).count()
    last_24h_partial = last_24h.filter(status=Deployment.Status.PARTIAL).count()
    last_24h_failed = last_24h.filter(status=Deployment.Status.FAILED).count()

    agent_coverage_pct = (
        int(round(agents_online * 100 / hosts_managed))
        if hosts_managed else 0
    )

    return {
        "hosts_total": hosts_total,
        "hosts_managed": hosts_managed,
        "hosts_no_agent": hosts_no_agent,
        "agents_total": agents_total,
        "agents_online": agents_online,
        "agents_offline": agents_offline,
        "agent_coverage_pct": agent_coverage_pct,
        "active_total": active_total,
        "last_24h_total": last_24h_total,
        "last_24h_success": last_24h_success,
        "last_24h_partial": last_24h_partial,
        "last_24h_failed": last_24h_failed,
        "generated_at": now,
    }


def recent_deployments(user, limit: int = RECENT_DEPLOYMENTS_LIMIT):
    return (
        Deployment.objects
        .filter(deployment_scope_q(user))
        .select_related("host", "host__domain", "host__host_set")
        .order_by("-created_at")[:limit]
    )


def active_deployments(user, limit: int = 20):
    return (
        Deployment.objects
        .filter(
            deployment_scope_q(user),
            status__in=[
                Deployment.Status.PENDING,
                Deployment.Status.DISPATCHED,
                Deployment.Status.RUNNING,
            ],
        )
        .select_related("host", "host__domain")
        .order_by("-priority", "created_at")[:limit]
    )


def deployment_trend(user, days: int = TREND_DAYS) -> list[dict]:
    now = timezone.now()
    since = (now - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )

    rows = (
        Deployment.objects
        .filter(deployment_scope_q(user), created_at__gte=since)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(
            total=Count("id"),
            success=Count("id", filter=Q(status=Deployment.Status.SUCCESS)),
            partial=Count("id", filter=Q(status=Deployment.Status.PARTIAL)),
            failed=Count("id", filter=Q(status=Deployment.Status.FAILED)),
        )
        .order_by("day")
    )

    by_day = {row["day"]: row for row in rows}
    result: list[dict] = []
    max_total = max((r["total"] for r in rows), default=1) or 1

    for i in range(days):
        d = (since + timedelta(days=i)).date()
        row = by_day.get(d, {
            "total": 0, "success": 0, "partial": 0, "failed": 0,
        })
        result.append({
            "date": d,
            "total": row["total"],
            "success": row["success"],
            "partial": row["partial"],
            "failed": row["failed"],
            "height_pct": int(round(row["total"] * 100 / max_total)) if max_total else 0,
        })

    return result


def domains_overview(user, limit: int = 10) -> list[dict]:
    online_cutoff = timezone.now() - ONLINE_THRESHOLD

    qs = (
        Domain.objects
        .filter(domain_scope_q(user))
        .annotate(
            hosts_total=Count("hosts", distinct=True),
            hosts_managed=Count(
                "hosts", filter=Q(hosts__managed=True), distinct=True,
            ),
            hosts_no_agent=Count(
                "hosts",
                filter=Q(hosts__managed=True, hosts__agent__isnull=True),
                distinct=True,
            ),
            agents_online=Count(
                "hosts__agent",
                filter=Q(hosts__agent__is_active=True,
                         hosts__agent__last_seen_at__gte=online_cutoff),
                distinct=True,
            ),
        )
        .order_by("-hosts_total", "name")[:limit]
    )

    result: list[dict] = []
    for d in qs:
        coverage = (
            int(round(d.agents_online * 100 / d.hosts_managed))
            if d.hosts_managed else 0
        )
        result.append({
            "domain": d,
            "hosts_total": d.hosts_total,
            "hosts_managed": d.hosts_managed,
            "hosts_no_agent": d.hosts_no_agent,
            "agents_online": d.agents_online,
            "coverage_pct": coverage,
        })
    return result