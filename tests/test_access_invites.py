import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone

from apps.access.models import (
    AuthAuditLog, Invitation, RoleAssignment,
)
from apps.access.roles import Role, ScopeType
from apps.access.services import (
    accept_invitation, approve_invitation, create_invitation,
    create_invitation_and_send, resend_invitation, revoke_invitation,
)
from apps.inventory.models import Domain

User = get_user_model()


@pytest.fixture
def d1(db):
    return Domain.objects.create(name="test.local")


@pytest.fixture
def su(db):
    u = User.objects.create_user("su", password="x")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.fixture
def su2(db):
    u = User.objects.create_user("su2", password="x")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.fixture
def admin(db, d1):
    u = User.objects.create_user("admin", password="x")
    RoleAssignment.objects.create(
        user=u, role="admin", scope_type="domain", scope_id=d1.pk,
    )
    return u


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_create_invitation_operator_sends_email(su, d1):
    inv, token, sent = create_invitation_and_send(
        email="newop@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    assert inv.status == Invitation.Status.PENDING
    assert sent
    assert len(mail.outbox) == 1
    assert "newop@test.local" in mail.outbox[0].to
    assert token in mail.outbox[0].body


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_create_invitation_admin_pending_approval(su, d1):
    inv, token, sent = create_invitation_and_send(
        email="newadmin@test.local", role="admin",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    assert inv.status == Invitation.Status.PENDING_APPROVAL
    assert not sent
    assert len(mail.outbox) == 0
    assert inv.required_approvals() == 2


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_consensus_flow(su, su2, d1):
    inv, _token, _sent = create_invitation_and_send(
        email="newadmin@test.local", role="admin",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    assert inv.status == Invitation.Status.PENDING_APPROVAL

    # su не может подтвердить свой же
    with pytest.raises(PermissionError):
        approve_invitation(inv, by_user=su)

    approve_invitation(inv, by_user=su2)
    inv.refresh_from_db()
    assert inv.status == Invitation.Status.PENDING


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_accept_invitation(su, d1):
    inv, token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    user = accept_invitation(
        inv, token=token, username="newuser", password="password123",
    )
    assert user.email == "new@test.local"
    assert RoleAssignment.objects.filter(
        user=user, role="operator",
    ).exists()

    inv.refresh_from_db()
    assert inv.status == Invitation.Status.ACCEPTED
    assert inv.accepted_by_id == user.pk


@pytest.mark.django_db
def test_accept_wrong_token(su, d1):
    inv, _token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    with pytest.raises(PermissionError):
        accept_invitation(inv, token="wrongtoken",
                          username="x", password="password123")


@pytest.mark.django_db
def test_accept_expired(su, d1):
    inv, token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    inv.expires_at = timezone.now() - timezone.timedelta(hours=1)
    inv.save()

    with pytest.raises(ValueError, match="истёк"):
        accept_invitation(inv, token=token,
                          username="x", password="password123")


@pytest.mark.django_db
def test_accept_duplicate_username(su, d1):
    User.objects.create_user("taken", password="x")
    inv, token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    with pytest.raises(ValueError, match="занят"):
        accept_invitation(inv, token=token,
                          username="taken", password="password123")


@pytest.mark.django_db
def test_revoke_invitation(su, d1):
    inv, _token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    revoke_invitation(inv, by_user=su, reason="no longer needed")
    inv.refresh_from_db()
    assert inv.status == Invitation.Status.REVOKED


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_resend_invitation(su, d1):
    inv, _token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    old_hash = inv.token_hash
    sent = resend_invitation(inv, by_user=su)
    assert sent
    inv.refresh_from_db()
    assert inv.token_hash != old_hash


# --- UI-тесты ---

@pytest.mark.django_db
def test_invite_accept_page_valid_token(su, d1):
    inv, token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    c = Client()
    r = c.get(f"/access/invite/{token}/")
    assert r.status_code == 200
    assert "new@test.local" in r.content.decode()


@pytest.mark.django_db
def test_invite_accept_page_invalid_token():
    c = Client()
    r = c.get("/access/invite/bogus/")
    assert r.status_code == 404


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_invite_accept_post(su, d1):
    inv, token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    c = Client()
    r = c.post(f"/access/invite/{token}/", {
        "username": "newuser",
        "password": "password123",
        "password2": "password123",
        "full_name": "New User",
    })
    assert r.status_code == 302
    assert User.objects.filter(username="newuser").exists()


@pytest.mark.django_db
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_invite_accept_post_password_mismatch(su, d1):
    inv, token = create_invitation(
        email="new@test.local", role="operator",
        scope_type="domain", scope_id=d1.pk,
        invited_by=su,
    )
    c = Client()
    r = c.post(f"/access/invite/{token}/", {
        "username": "newuser",
        "password": "password123",
        "password2": "different",
    })
    assert r.status_code == 200
    assert not User.objects.filter(username="newuser").exists()