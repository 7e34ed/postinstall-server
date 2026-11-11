import base64

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from apps.secrets import blob as b
from apps.secrets.models import SecretAccessLog, ServerKey
from apps.secrets.runtime import runtime

User = get_user_model()


@pytest.mark.django_db
def test_items_list_empty(admin_client):
    r = admin_client.get("/admin/secrets/items/")
    assert r.status_code == 200
    assert "Секретов пока нет" in r.content.decode()


@pytest.mark.django_db
def test_item_create(admin_client):
    r = admin_client.post("/admin/secrets/items/new/", {
        "path": "credentials/test/password",
        "key": "value",
        "value": "s3cret",
    })
    assert r.status_code == 302
    assert runtime.get("credentials/test/password", "value") == "s3cret"


@pytest.mark.django_db
def test_item_create_invalid_path(admin_client):
    r = admin_client.post("/admin/secrets/items/new/", {
        "path": "../etc/passwd",
        "key": "value",
        "value": "x",
    })
    assert r.status_code == 200
    assert ".." in r.content.decode()


@pytest.mark.django_db
def test_item_edit(admin_client):
    from apps.secrets.services import get_secret, set_secret

    set_secret("a/b", "value", "old")

    r = admin_client.post("/admin/secrets/items/a/b/", {
        "v__value": "new",
    })
    assert r.status_code == 302

    # assert runtime.get("a/b", "value") == "new"
    assert get_secret("a/b", "value") == "new"

@pytest.mark.django_db
def test_item_edit_add_key(admin_client):
    from apps.secrets.services import get_secret, set_secret

    # runtime.set("a/b", "value", "x")
    # runtime.persist()
    set_secret("a/b", "value", "x")

    r = admin_client.post("/admin/secrets/items/a/b/", {
        "v__value": "",
        "new_key": "extra",
        "new_value": "y",
    })
    assert r.status_code == 302
    # assert runtime.get("a/b", "value") == "x"
    # assert runtime.get("a/b", "extra") == "y"

    assert get_secret("a/b", "value") == "x"
    assert get_secret("a/b", "extra") == "y"

@pytest.mark.django_db
def test_item_delete(admin_client):
    from apps.secrets.services import set_secret

    set_secret("a/b", "value", "x")

    r = admin_client.post("/admin/secrets/items/a/b/delete/")
    assert r.status_code == 302
    assert not runtime.exists("a/b")


@pytest.mark.django_db
def test_item_key_delete(admin_client):
    from apps.secrets.services import get_secret, set_secret

    set_secret("a/b", "value", "x")
    set_secret("a/b", "extra", "y")

    r = admin_client.post("/admin/secrets/items/a/b/keys/extra/delete/")
    assert r.status_code == 302
    assert get_secret("a/b", "value") == "x"
    assert get_secret("a/b", "extra") is None


@pytest.mark.django_db
def test_item_create_duplicate(admin_client):
    from apps.secrets.services import set_secret

    # runtime.set("a/b", "value", "x")
    # runtime.persist()
    set_secret("a/b", "value", "x")

    r = admin_client.post("/admin/secrets/items/new/", {
        "path": "a/b",
        "key": "other",
        "value": "y",
    })
    assert r.status_code == 200
    assert "уже существует" in r.content.decode()


@pytest.mark.django_db
def test_items_search(admin_client):
    from apps.secrets.services import set_secret
    
    set_secret("credentials/foo", "value", "x")
    set_secret("other/bar", "value", "y")
    
    r = admin_client.get("/admin/secrets/items/?q=cred")
    assert "credentials/foo" in r.content.decode()


@pytest.mark.django_db
def test_requires_admin(admin_client):
    from django.test import Client as _C
    c = _C()   # анонимный
    r = c.get("/admin/secrets/items/")
    # staff_member_required редиректит на /admin/login/
    assert r.status_code == 302


@pytest.mark.django_db
def test_sealed_redirects(db):
    salt = b.new_salt()
    kek = b.derive_kek("m", salt)
    blob = b.encrypt_blob(b.empty_blob(), kek)
    ServerKey.objects.create(
        salt=base64.b64encode(salt).decode(),
        blob=base64.b64encode(blob).decode(),
    )
    runtime.seal()

    user = User.objects.create_superuser("admin2", "b@b.b", "x")
    c = Client()
    c.force_login(user)
    r = c.get("/admin/secrets/items/")
    # middleware отдаёт 503
    assert r.status_code == 503