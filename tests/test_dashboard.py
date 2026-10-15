import pytest
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone

from apps.dashboard.services import (
    collect_metrics, deployment_trend, domains_overview, recent_deployments,
)
from apps.deploy.models import Agent, Deployment
from apps.inventory.models import Domain, Host, HostSet

User = get_user_model()


@pytest.fixture
def host(db):
    d = Domain.objects.create(name="test.local")
    s = HostSet.objects.create(domain=d, name="default", platform="linux.debian")
    return Host.objects.create(domain=d, host_set=s, hostname="web1", managed=True)


@pytest.fixture
def admin_client(db):
    user = User.objects.create_superuser("admin", "a@a.a", "x")
    c = Client()
    c.force_login(user)
    return c


@pytest.mark.django_db
def test_metrics_empty(db):
    m = collect_metrics()
    assert m["hosts_total"] == 0
    assert m["agents_total"] == 0
    assert m["active_total"] == 0


@pytest.mark.django_db
def test_metrics_with_data(host):
    Agent.objects.create(
        host=host, pubkey_ed25519="k1", pubkey_x25519="k2",
        last_seen_at=timezone.now(),
    )
    Deployment.objects.create(host=host)
    m = collect_metrics()
    assert m["hosts_total"] == 1
    assert m["hosts_managed"] == 1
    assert m["agents_online"] == 1
    assert m["agent_coverage_pct"] == 100
    assert m["active_total"] == 1


@pytest.mark.django_db
def test_agent_offline(host):
    old = timezone.now() - timedelta(hours=1)
    Agent.objects.create(
        host=host, pubkey_ed25519="k1", pubkey_x25519="k2",
        last_seen_at=old,
    )
    m = collect_metrics()
    assert m["agents_online"] == 0
    assert m["agents_offline"] == 1


@pytest.mark.django_db
def test_host_no_agent(host):
    m = collect_metrics()
    assert m["hosts_no_agent"] == 1


@pytest.mark.django_db
def test_trend(host):
    Deployment.objects.create(host=host, status="success")
    Deployment.objects.create(host=host, status="failed")
    trend = deployment_trend(days=7)
    assert len(trend) == 7
    today = trend[-1]
    assert today["total"] == 2
    assert today["success"] == 1
    assert today["failed"] == 1


@pytest.mark.django_db
def test_recent_deployments_order(host):
    Deployment.objects.create(host=host, status="success")
    Deployment.objects.create(host=host, status="pending")
    r = list(recent_deployments(limit=10))
    assert len(r) == 2


@pytest.mark.django_db
def test_domains_overview(host):
    result = domains_overview()
    assert len(result) == 1
    assert result[0]["domain"].name == "test.local"
    assert result[0]["hosts_total"] == 1


@pytest.mark.django_db
def test_dashboard_page(admin_client):
    r = admin_client.get("/")
    assert r.status_code == 200
    assert "Обзор парка" in r.content.decode()


@pytest.mark.django_db
def test_metrics_partial(admin_client):
    r = admin_client.get("/partial/metrics/")
    assert r.status_code == 200
    assert "Хостов" in r.content.decode()


@pytest.mark.django_db
def test_dashboard_requires_auth(db):
    c = Client()
    r = c.get("/")
    assert r.status_code == 302
    assert "/admin/login/" in r.url