import base64

import pytest
from django.contrib.auth import get_user_model

from apps.access.models import RoleAssignment
from apps.access.roles import Role, ScopeType
from apps.secrets import blob as b
from apps.secrets.models import (
    SecretAccessGrant, SecretOwnershipTransfer, ServerKey,
)
from apps.secrets.runtime import runtime
from apps.secrets.services import (
    approve_transfer, can_user_read, can_user_write, get_ref,
    get_secret, get_secret_for_user, grant_access, initiate_transfer,
    revoke_grant, set_secret,
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
def owner(db):
    return User.objects.create_user("owner")


@pytest.fixture
def other(db):
    return User.objects.create_user("other")


@pytest.fixture
def supervisor(db):
    u = User.objects.create_user("sup")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.mark.django_db
def test_owner_can_read(unsealed, owner):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    assert can_user_read(owner, ref)


@pytest.mark.django_db
def test_other_cannot_read(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    assert not can_user_read(other, ref)


@pytest.mark.django_db
def test_other_cannot_write(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    assert not can_user_write(other, ref)


@pytest.mark.django_db
def test_get_secret_for_user_denies(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    assert get_secret_for_user(other, "a/b", "value") is None
    assert get_secret_for_user(owner, "a/b", "value") == "x"


@pytest.mark.django_db
def test_grant_allows_read(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")

    grant_access(ref, other, by_user=owner, reason="vacation cover")
    assert can_user_read(other, ref)
    assert get_secret_for_user(other, "a/b", "value") == "x"


@pytest.mark.django_db
def test_grant_does_not_allow_write(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    grant_access(ref, other, by_user=owner)
    assert not can_user_write(other, ref)


@pytest.mark.django_db
def test_non_owner_cannot_grant(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    with pytest.raises(PermissionError):
        grant_access(ref, other, by_user=other)


@pytest.mark.django_db
def test_grant_revoke_by_owner(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    grant = grant_access(ref, other, by_user=owner)

    revoke_grant(grant, by_user=owner)
    assert not can_user_read(other, ref)


@pytest.mark.django_db
def test_supervisor_can_read_metadata_not_value(
    unsealed, owner, supervisor,
):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")

    # SUPERVISOR не читает значение
    assert get_secret_for_user(supervisor, "a/b", "value") is None


@pytest.mark.django_db
def test_transfer_requires_two_supervisors(
    unsealed, owner, other, supervisor,
):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")

    transfer = initiate_transfer(ref, other, by_user=supervisor)
    assert transfer.status == SecretOwnershipTransfer.Status.PENDING

    # нельзя подтвердить тому же
    with pytest.raises(PermissionError):
        approve_transfer(transfer, by_user=supervisor)

    # другой SUPERVISOR
    su2 = User.objects.create_user("su2")
    RoleAssignment.objects.create(
        user=su2, role="supervisor", scope_type="global", scope_id=0,
    )
    approve_transfer(transfer, by_user=su2)

    ref.refresh_from_db()
    assert ref.owner_id == other.pk


@pytest.mark.django_db
def test_transfer_non_supervisor_blocked(unsealed, owner, other):
    set_secret("a/b", "value", "x", user=owner)
    ref = get_ref("a/b")
    with pytest.raises(PermissionError):
        initiate_transfer(ref, other, by_user=owner)