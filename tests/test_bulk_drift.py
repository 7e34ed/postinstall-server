from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone

from apps.deploy.models import BulkDeployment, Deployment
from apps.deploy.services import (
    bulk_create_deployments,
    cancel_bulk,
    compute_config_hash,
    update_host_hash_after_deployment,
    update_host_state,
)
from apps.inventory.models import Domain, Host, HostSet

User = get_user_model()


@pytest.fixture
def domain(db):
    return Domain.objects.create(name="test.local")


@pytest.fixture
def host_set(domain):
    return HostSet.objects.create(
        domain=domain, name="web", platform="linux.debian",
        common_config={"general": {"allowed_ips": ["10.0.0.0/8"], "allowed_ports": [22]}},
    )


@pytest.fixture
def hosts(domain, host_set):
    return [
        Host.objects.create(domain=domain, host_set=host_set,
                            hostname=f"web{i}", managed=True)
        for i in (1, 2, 3)
    ]


@pytest.fixture
def admin_client(db):
    user = User.objects.create_superuser("admin", "a@a.a", "x")
    c = Client()
    c.force_login(user)
    return c


@pytest.mark.django_db
def test_bulk_create(hosts):
    ids = [h.pk for h in hosts]
    result = bulk_create_deployments(ids)
    assert result["bulk"].total == 3
    assert len(result["created"]) == 3
    assert result["bulk"].status == BulkDeployment.Status.RUNNING


@pytest.mark.django_db
def test_bulk_skips_active(hosts):
    from apps.deploy.services import create_deployment
    create_deployment(hosts[0])

    ids = [h.pk for h in hosts]
    result = bulk_create_deployments(ids)
    assert len(result["created"]) == 2
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["host"].pk == hosts[0].pk


@pytest.mark.django_db
def test_bulk_recompute_on_success(hosts):
    ids = [h.pk for h in hosts]
    result = bulk_create_deployments(ids)
    bulk = result["bulk"]
    for d in result["created"][:2]:
        d.status = Deployment.Status.SUCCESS
        d.save()

    bulk.refresh_from_db()
    assert bulk.succeeded == 2
    assert bulk.status == BulkDeployment.Status.RUNNING

    result["created"][2].status = Deployment.Status.SUCCESS
    result["created"][2].save()
    bulk.refresh_from_db()
    assert bulk.succeeded == 3
    assert bulk.status == BulkDeployment.Status.SUCCESS


@pytest.mark.django_db
def test_bulk_cancel(hosts):
    ids = [h.pk for h in hosts]
    result = bulk_create_deployments(ids)
    bulk = result["bulk"]
    n = cancel_bulk(bulk)
    assert n == 3
    bulk.refresh_from_db()
    assert bulk.cancelled_count == 3
    assert bulk.status == BulkDeployment.Status.CANCELLED


@pytest.mark.django_db
def test_compute_config_hash_stable(hosts):
    h = hosts[0]
    a = compute_config_hash(h)
    b = compute_config_hash(h)
    assert a == b
    assert len(a) == 64


@pytest.mark.django_db
def test_drift_detected_after_config_change(hosts):
    h = hosts[0]
    h.last_deployed_config_hash = compute_config_hash(h)
    h.save()

    state = update_host_state(h)
    assert state["state"] == "clean"

    # меняем конфиг хоста
    h.overrides = {"general": {"allowed_ports": [22, 443]}}
    h.save()

    state = update_host_state(h)
    assert state["state"] == "drift"
    h.refresh_from_db()
    assert h.drift_detected_at is not None


@pytest.mark.django_db
def test_unsynced_state(hosts):
    h = hosts[0]
    state = update_host_state(h)
    assert state["state"] == "unsynced"


@pytest.mark.django_db
def test_hash_updated_on_success(hosts):
    h = hosts[0]
    d = Deployment.objects.create(host=h)
    assert not h.last_deployed_config_hash

    d.status = Deployment.Status.SUCCESS
    d.save()
    h.refresh_from_db()
    assert h.last_deployed_config_hash
    assert h.last_deployed_at is not None


@pytest.mark.django_db
def test_bulk_apply_view(admin_client, hosts):
    ids = [h.pk for h in hosts]
    r = admin_client.post("/deploy/bulk/apply/",
                          {"host_ids": [str(x) for x in ids]})
    assert r.status_code in (302, 204)
    assert BulkDeployment.objects.count() == 1
    assert Deployment.objects.count() == 3


@pytest.mark.django_db
def test_drift_sync_all_view(admin_client, hosts):
    now = timezone.now()
    for h in hosts[:2]:
        h.drift_detected_at = now
        h.save()

    r = admin_client.post("/deploy/drift/sync-all/")
    assert r.status_code == 302
    assert BulkDeployment.objects.count() == 1
    assert BulkDeployment.objects.first().total == 2


@pytest.mark.django_db
def test_drift_list_view(admin_client, hosts):
    now = timezone.now()
    hosts[0].drift_detected_at = now
    hosts[0].save()

    r = admin_client.get("/deploy/drift/")
    assert r.status_code == 200
    body = r.content.decode()
    assert hosts[0].hostname in body
    assert hosts[1].hostname not in body


@pytest.mark.django_db
def test_bulk_detail_page(admin_client, hosts):
    ids = [h.pk for h in hosts]
    result = bulk_create_deployments(ids)
    r = admin_client.get(f"/deploy/bulk/{result['bulk'].id}/")
    assert r.status_code == 200
    assert result["bulk"].name in r.content.decode()