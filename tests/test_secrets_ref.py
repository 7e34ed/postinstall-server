import base64

import pytest

from apps.secrets import blob as b
from apps.secrets.models import SecretRef, ServerKey
from apps.secrets.runtime import runtime
from apps.secrets.services import (
    delete_secret,
    get_ref,
    get_secret,
    list_refs,
    set_secret,
    touch_ref,
)


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


@pytest.mark.django_db
def test_set_secret_creates_ref(unsealed):
    set_secret("a/b", "value", "x", display_name="My secret")
    ref = SecretRef.objects.get(path="a/b", key="value")
    assert ref.display_name == "My secret"
    assert ref.backend == "local"
    assert ref.access_count == 0


@pytest.mark.django_db
def test_set_secret_twice_keeps_owner(unsealed):
    from django.contrib.auth import get_user_model
    
    User = get_user_model()
    alice = User.objects.create_user("alice")
    bob = User.objects.create_user("bob")

    set_secret("a/b", "value", "v1", user=alice)
    ref = SecretRef.objects.get(path="a/b")
    assert ref.owner_id == alice.pk

    set_secret("a/b", "value", "v2", user=bob)
    ref.refresh_from_db()
    # owner не перезаписан
    assert ref.owner_id == alice.pk


@pytest.mark.django_db
def test_set_secret_creates_ref_without_user(unsealed):
    """Без user — owner NULL (миграционная фаза)."""
    set_secret("a/b", "value", "x")
    ref = SecretRef.objects.get(path="a/b")
    assert ref.owner_id is None


@pytest.mark.django_db
def test_get_secret_touches_ref(unsealed):
    set_secret("a/b", "value", "x")
    ref = SecretRef.objects.get(path="a/b")
    assert ref.access_count == 0

    get_secret("a/b", "value")
    ref.refresh_from_db()
    assert ref.access_count == 1
    assert ref.last_accessed_at is not None

    get_secret("a/b", "value")
    ref.refresh_from_db()
    assert ref.access_count == 2


@pytest.mark.django_db
def test_get_secret_no_audit_does_not_touch(unsealed):
    set_secret("a/b", "value", "x")
    ref = SecretRef.objects.get(path="a/b")

    get_secret("a/b", "value", audit=False)
    ref.refresh_from_db()
    assert ref.access_count == 0


@pytest.mark.django_db
def test_delete_secret_removes_ref(unsealed):
    set_secret("a/b", "value", "x")
    assert SecretRef.objects.filter(path="a/b").exists()

    delete_secret("a/b")
    assert not SecretRef.objects.filter(path="a/b").exists()
    assert get_secret("a/b", "value", audit=False) is None


@pytest.mark.django_db
def test_get_ref(unsealed):
    set_secret("x/y", "password", "p")
    ref = get_ref("x/y", "password")
    assert ref is not None
    assert ref.path == "x/y"


@pytest.mark.django_db
def test_list_refs(unsealed):
    set_secret("a/1", "value", "x")
    set_secret("a/2", "value", "y")
    set_secret("b/3", "value", "z")

    all_refs = list_refs()
    assert len(all_refs) == 3

    a_refs = list_refs(prefix="a/")
    assert len(a_refs) == 2

    by_backend = list_refs(backend="local")
    assert len(by_backend) == 3

    by_backend_missing = list_refs(backend="openbao")
    assert len(by_backend_missing) == 0


@pytest.mark.django_db
def test_touch_ref_direct(unsealed):
    set_secret("a/b", "value", "x")
    touch_ref("a/b", "value")
    ref = get_ref("a/b", "value")
    assert ref.access_count == 1


@pytest.mark.django_db
def test_ref_scope(unsealed):
    from apps.inventory.models import Domain, Host, HostSet

    d = Domain.objects.create(name="test.local")
    hs = HostSet.objects.create(domain=d, name="web", platform="linux.debian")
    h = Host.objects.create(domain=d, host_set=hs, hostname="web1")

    set_secret("a/b", "value", "x", domain=d, host_set=hs, host=h)
    ref = SecretRef.objects.get(path="a/b")
    assert ref.domain_id == d.pk
    assert ref.host_set_id == hs.pk
    assert ref.host_id == h.pk


@pytest.mark.django_db
def test_unique_constraint(unsealed):
    set_secret("a/b", "value", "x")
    # повторная запись с той же тройкой — не создаёт дубль
    set_secret("a/b", "value", "y")
    assert SecretRef.objects.filter(path="a/b", key="value").count() == 1