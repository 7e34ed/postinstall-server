import pytest
from django.core.exceptions import ValidationError
from django.test import Client
from django.contrib.auth import get_user_model

from apps.deploy.models import Agent, Deployment
from apps.deploy.services import active_deployment_for, create_deployment
from apps.inventory.models import Domain, Host, HostSet

User = get_user_model()


@pytest.fixture
def host(db):
    d = Domain.objects.create(name="test.local")
    s = HostSet.objects.create(domain=d, name="default", platform="linux.debian")
    return Host.objects.create(domain=d, host_set=s, hostname="web1")


@pytest.fixture
def admin_client(db):
    user = User.objects.create_superuser("admin", "a@a.a", "x")
    c = Client()
    c.force_login(user)
    return c


@pytest.mark.django_db
def test_create_deployment(host):
    d = create_deployment(host)
    assert d.status == Deployment.Status.PENDING
    assert d.host == host


@pytest.mark.django_db
def test_create_deployment_rejects_active(host):
    create_deployment(host)
    with pytest.raises(ValidationError):
        create_deployment(host)


@pytest.mark.django_db
def test_cancel_marks_cancelled(admin_client, host):
    d = create_deployment(host)
    r = admin_client.post(f"/deploy/{d.id}/cancel/")
    assert r.status_code in (302, 204)
    d.refresh_from_db()
    assert d.status == Deployment.Status.CANCELLED


@pytest.mark.django_db
def test_retry_creates_new(admin_client, host):
    d = create_deployment(host)
    d.status = Deployment.Status.FAILED
    d.save()

    r = admin_client.post(f"/deploy/{d.id}/retry/")
    assert r.status_code in (302, 204)
    assert Deployment.objects.filter(host=host).count() == 2


@pytest.mark.django_db
def test_apply_from_host_page(admin_client, host):
    r = admin_client.post(f"/deploy/hosts/{host.pk}/apply/")
    assert r.status_code in (302, 204)
    assert Deployment.objects.filter(host=host).count() == 1


@pytest.mark.django_db
def test_status_endpoint(admin_client, host):
    d = create_deployment(host)
    r = admin_client.get(f"/deploy/{d.id}/status/")
    assert r.status_code == 200
    assert "Ожидает" in r.content.decode()