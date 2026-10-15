import base64

import pytest

from apps.secrets import blob as b
from apps.secrets.models import ServerKey
from apps.secrets.runtime import SecretsSealed, runtime


@pytest.fixture
def fresh_runtime(db):
    # создаём ServerKey через init-путь
    salt = b.new_salt()
    kek = b.derive_kek("master", salt)
    blob = b.encrypt_blob(b.empty_blob(), kek)
    ServerKey.objects.create(
        salt=base64.b64encode(salt).decode(),
        blob=base64.b64encode(blob).decode(),
    )
    runtime.seal()
    yield
    runtime.seal()


@pytest.mark.django_db
def test_status_uninitialized():
    s = runtime.status()
    assert s.state == "uninitialized"


@pytest.mark.django_db
def test_status_sealed(fresh_runtime):
    s = runtime.status()
    assert s.state == "sealed"


@pytest.mark.django_db
def test_unlock_wrong_key(fresh_runtime):
    with pytest.raises(SecretsSealed):
        runtime.unlock("wrong")


@pytest.mark.django_db
def test_unlock_ok(fresh_runtime):
    runtime.unlock("master")
    assert runtime.is_unsealed()
    assert runtime.status().state == "unsealed"


@pytest.mark.django_db
def test_set_get(fresh_runtime):
    runtime.unlock("master")
    runtime.set("a/b", "value", "hello")
    assert runtime.get("a/b", "value") == "hello"


@pytest.mark.django_db
def test_persist_and_reload(fresh_runtime):
    runtime.unlock("master")
    runtime.set("a/c", "value", "x")
    runtime.persist()

    runtime.seal()
    runtime.unlock("master")
    assert runtime.get("a/c", "value") == "x"


@pytest.mark.django_db
def test_rotate(fresh_runtime):
    runtime.unlock("master")
    runtime.set("a/d", "value", "y")
    runtime.persist()

    runtime.rotate_master_key("master", "newmaster")
    runtime.seal()

    with pytest.raises(SecretsSealed):
        runtime.unlock("master")

    runtime.unlock("newmaster")
    assert runtime.get("a/d", "value") == "y"