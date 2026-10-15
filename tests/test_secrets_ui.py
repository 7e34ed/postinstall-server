import base64

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from apps.secrets import blob as b
from apps.secrets.models import SecretAccessLog, ServerKey
from apps.secrets.runtime import runtime

User = get_user_model()


@pytest.fixture
def admin_client(db):
    # создаём ServerKey и разблокируем
    salt = b.new_salt()
    kek = b.derive_kek("m", salt)
    blob = b.encrypt_blob(b.empty_blob(), kek)
    ServerKey.objects.create(
        salt=base64.b64encode(salt).decode(),
        blob=base64.b64encode(blob).decode(),
    )
    runtime.seal()
    runtime.unlock("m")

    user = User.objects.create_superuser("admin", "a@a.a", "x")
    c = Client()
    c.force_login(user)
    yield c
    runtime.seal()


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
    runtime.set("a/b", "value", "old")
    runtime.persist()

    r = admin_client.post("/admin/secrets/items/a/b/", {
        "v__value": "new",
    })
    assert r.status_code == 302
    assert runtime.get("a/b", "value") == "new"


@pytest.mark.django_db
def test_item_edit_add_key(admin_client):
    runtime.set("a/b", "value", "x")
    runtime.persist()

    r = admin_client.post("/admin/secrets/items/a/b/", {
        "v__value": "",
        "new_key": "extra",
        "new_value": "y",
    })
    assert r.status_code == 302
    assert runtime.get("a/b", "value") == "x"
    assert runtime.get("a/b", "extra") == "y"


@pytest.mark.django_db
def test_item_delete(admin_client):
    runtime.set("a/b", "value", "x")
    runtime.persist()

    r = admin_client.post("/admin/secrets/items/a/b/delete/")
    assert r.status_code == 302
    assert not runtime.exists("a/b")


@pytest.mark.django_db
def test_item_key_delete(admin_client):
    runtime.set("a/b", "value", "x")
    runtime.set("a/b", "extra", "y")
    runtime.persist()

    r = admin_client.post("/admin/secrets/items/a/b/keys/extra/delete/")
    assert r.status_code == 302
    assert runtime.get("a/b", "value") == "x"
    from apps.secrets.backends.base import SecretNotFound
    with pytest.raises(SecretNotFound):
        runtime.get("a/b", "extra")


@pytest.mark.django_db
def test_item_create_duplicate(admin_client):
    runtime.set("a/b", "value", "x")
    runtime.persist()

    r = admin_client.post("/admin/secrets/items/new/", {
        "path": "a/b",
        "key": "other",
        "value": "y",
    })
    assert r.status_code == 200
    assert "уже существует" in r.content.decode()


@pytest.mark.django_db
def test_items_search(admin_client):
    runtime.set("credentials/foo", "value", "x")
    runtime.set("other/bar", "value", "y")
    runtime.persist()

    r = admin_client.get("/admin/secrets/items/?q=creds")
    assert "credentials/foo" in r.content.decode()
    assert "other/bar" not in r.content.decode()


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