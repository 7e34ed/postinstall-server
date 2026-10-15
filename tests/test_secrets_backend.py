import base64

import pytest
from django.contrib.auth import get_user_model
from django.test import Client, override_settings

from apps.secrets import blob as b
from apps.secrets.backends import BACKEND_CLASSES, is_registered
from apps.secrets.models import SecretAccessLog, ServerKey
from apps.secrets.runtime import runtime
from apps.secrets.services import (
    get_active_backend, list_backends, set_active_backend,
    set_backend_credentials, test_backend,
    get_backend_credentials, delete_backend_credentials,
)

User = get_user_model()


@pytest.fixture
def unsealed(db):
    salt = b.new_salt()
    kek = b.derive_kek("m", salt)
    blob = b.encrypt_blob(b.empty_blob(), kek)
    ServerKey.objects.create(
        salt=base64.b64encode(salt).decode(),
        blob=base64.b64encode(blob).decode(),
    )
    runtime.seal()
    runtime.unlock("m")
    yield
    runtime.seal()


@pytest.fixture
def admin_client(db, unsealed):
    u = User.objects.create_superuser("admin", "a@a.a", "x")
    c = Client()
    c.force_login(u)
    yield c


def test_registered_backends():
    assert is_registered("local")
    assert is_registered("openbao")
    assert is_registered("keepass")


@pytest.mark.django_db
def test_default_active_backend(unsealed):
    assert get_active_backend() == "local"


@pytest.mark.django_db
def test_list_backends(unsealed):
    rows = list_backends()
    names = {r.name for r in rows}
    assert {"local", "openbao", "keepass"} <= names
    local = next(r for r in rows if r.name == "local")
    assert local.active
    assert local.health.get("status") == "ok"


@pytest.mark.django_db
def test_set_active_backend_rejects_unknown(unsealed):
    with pytest.raises(ValueError):
        set_active_backend("bogus")


@pytest.mark.django_db
def test_set_active_backend_openbao_no_creds(unsealed):
    # openbao без credentials — health не ok, переключение отклоняется
    ok = set_active_backend("openbao")
    assert not ok
    assert get_active_backend() == "local"


@pytest.mark.django_db
def test_set_backend_credentials(unsealed):
    set_backend_credentials("openbao", {
        "url": "https://openbao.test:8200",
        "token": "hvs.test",
        "mount": "secret",
    })
    creds = get_backend_credentials("openbao")
    assert creds["url"] == "https://openbao.test:8200"
    assert creds["token"] == "hvs.test"


@pytest.mark.django_db
def test_credentials_persisted(unsealed):
    set_backend_credentials("openbao", {"url": "u", "token": "t"})
    runtime.seal()
    runtime.unlock("m")
    assert get_backend_credentials("openbao") == {"url": "u", "token": "t"}


@pytest.mark.django_db
def test_delete_backend_credentials(unsealed):
    set_backend_credentials("openbao", {"url": "u", "token": "t"})
    delete_backend_credentials("openbao")
    assert get_backend_credentials("openbao") == {}


@pytest.mark.django_db
def test_test_backend_unknown(unsealed):
    assert test_backend("bogus")["status"] == "error"


@pytest.mark.django_db
def test_backend_change_audited(unsealed):
    set_backend_credentials("openbao", {"url": "u", "token": "t"})
    # health всё равно fail (нет реального сервера), поэтому set отклонится
    set_active_backend("openbao")
    log = SecretAccessLog.objects.filter(
        action=SecretAccessLog.Action.BACKEND_CHANGE,
    ).last()
    assert log is not None
    assert not log.success


@pytest.mark.django_db
def test_credentials_change_audited(unsealed):
    set_backend_credentials("openbao", {"url": "u", "token": "t"})
    log = SecretAccessLog.objects.filter(
        action=SecretAccessLog.Action.CREDENTIALS_CHANGE,
    ).last()
    assert log is not None
    assert log.success
    assert "url" in log.detail.get("keys", [])


# --- UI ---

@pytest.mark.django_db
def test_backend_page_renders(admin_client):
    r = admin_client.get("/admin/secrets/backend/")
    assert r.status_code == 200
    body = r.content.decode()
    assert "Secrets backend" in body
    assert "local" in body
    assert "openbao" in body


@pytest.mark.django_db
def test_backend_credentials_save(admin_client):
    r = admin_client.post("/admin/secrets/backend/credentials/save/", {
        "name": "openbao",
        "url": "https://test:8200",
        "token": "hvs.test",
        "mount": "secret",
        "namespace": "",
    })
    assert r.status_code in (302, 200)
    creds = get_backend_credentials("openbao")
    assert creds["url"] == "https://test:8200"
    assert creds["token"] == "hvs.test"


@pytest.mark.django_db
def test_backend_credentials_save_keeps_secret_on_blank(admin_client):
    set_backend_credentials("openbao", {"url": "u", "token": "orig"})
    admin_client.post("/admin/secrets/backend/credentials/save/", {
        "name": "openbao",
        "url": "u2",
        "token": "",   # пустое — не менять
        "mount": "secret",
        "namespace": "",
    })
    creds = get_backend_credentials("openbao")
    assert creds["url"] == "u2"
    assert creds["token"] == "orig"


@pytest.mark.django_db
def test_backend_credentials_save_keeps_secret_on_mask(admin_client):
    set_backend_credentials("openbao", {"url": "u", "token": "orig"})
    admin_client.post("/admin/secrets/backend/credentials/save/", {
        "name": "openbao",
        "url": "u2",
        "token": "••••••••",   # маска — не менять
        "mount": "secret",
        "namespace": "",
    })
    creds = get_backend_credentials("openbao")
    assert creds["token"] == "orig"


@pytest.mark.django_db
def test_backend_requires_unsealed(admin_client):
    runtime.seal()
    r = admin_client.get("/admin/secrets/backend/")
    assert r.status_code == 302   # redirect на /admin/


@pytest.mark.django_db
def test_backend_test_endpoint(admin_client):
    r = admin_client.post("/admin/secrets/backend/test/", {"name": "local"})
    assert r.status_code == 302