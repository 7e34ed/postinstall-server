import pytest
from django.test import Client

from apps.secrets import blob as b
from apps.secrets.models import ServerKey
from apps.secrets.runtime import runtime


@pytest.fixture
def sealed(db):
    import base64
    salt = b.new_salt()
    kek = b.derive_kek("m", salt)
    blob = b.encrypt_blob(b.empty_blob(), kek)
    ServerKey.objects.create(
        salt=base64.b64encode(salt).decode(),
        blob=base64.b64encode(blob).decode(),
    )
    runtime.seal()
    yield
    runtime.seal()


@pytest.mark.django_db
def test_health_ok_when_unsealed(sealed):
    runtime.unlock("m")
    c = Client()
    r = c.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["secrets"]["state"] == "unsealed"


@pytest.mark.django_db
def test_health_503_when_sealed(sealed):
    c = Client()
    r = c.get("/api/v1/health")
    assert r.status_code == 503
    assert r.json()["secrets"]["state"] == "sealed"


@pytest.mark.django_db
def test_admin_blocked_when_sealed(sealed):
    c = Client()
    r = c.get("/admin/")
    assert r.status_code == 503
    assert "Секреты заблокированы" in r.content.decode()


@pytest.mark.django_db
def test_static_exempt(sealed):
    c = Client()
    r = c.get("/static/nonexistent.css")
    assert r.status_code in (200, 301, 302, 404)