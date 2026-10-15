import pytest
from django.contrib.auth import get_user_model
from django.test import Client, override_settings
from django.utils import timezone

from apps.access.models import (
    AccessReviewItem, AccessReviewRun, AuthAuditLog,
    BreakGlassAccount, RoleAssignment,
)
from apps.access.recovery_kit import (
    RecoveryKitData, generate_recovery_codes, write_recovery_kit,
)
from apps.access.services import (
    auto_disable_expired_break_glass,
    confirm_review_item, disable_break_glass, enable_break_glass,
    ensure_break_glass_account, expire_overdue_review_items,
    revoke_review_item, start_access_review,
)

User = get_user_model()


@pytest.fixture
def su(db):
    u = User.objects.create_user("su")
    RoleAssignment.objects.create(
        user=u, role="supervisor", scope_type="global", scope_id=0,
    )
    return u


@pytest.fixture
def target(db):
    return User.objects.create_user("target")


# --- Break-glass ---

@pytest.mark.django_db
def test_break_glass_created(db, su):
    user, password = ensure_break_glass_account(created_by=su)
    assert user.username == "break-glass"
    assert not user.is_active
    assert password
    assert BreakGlassAccount.objects.count() == 1


@pytest.mark.django_db
def test_break_glass_enable_disable(db, su):
    user, _ = ensure_break_glass_account(created_by=su)
    enable_break_glass(by_user=su, reason="test")
    user.refresh_from_db()
    assert user.is_active
    account = BreakGlassAccount.get()
    assert account.is_currently_active()

    disable_break_glass(by_user=su)
    user.refresh_from_db()
    assert not user.is_active


@pytest.mark.django_db
def test_break_glass_requires_supervisor(db, target):
    ensure_break_glass_account(created_by=None)
    with pytest.raises(PermissionError):
        enable_break_glass(by_user=target, reason="malicious")


@pytest.mark.django_db
def test_break_glass_auto_disable(db, su):
    user, _ = ensure_break_glass_account(created_by=su)
    enable_break_glass(by_user=su, reason="test")

    account = BreakGlassAccount.get()
    account.enabled_at = timezone.now() - timezone.timedelta(hours=25)
    account.save(update_fields=["enabled_at"])

    n = auto_disable_expired_break_glass()
    assert n == 1
    user.refresh_from_db()
    assert not user.is_active


@pytest.mark.django_db
def test_break_glass_audit(db, su):
    ensure_break_glass_account(created_by=su)
    enable_break_glass(by_user=su, reason="test")
    log = AuthAuditLog.objects.filter(
        event=AuthAuditLog.Event.BREAK_GLASS_ENABLED,
    ).last()
    assert log is not None


# --- Recovery kit ---

@pytest.mark.django_db
def test_recovery_kit_txt(tmp_path):
    kit = RecoveryKitData(
        username="admin",
        password="p@ssw0rd",
        recovery_codes=generate_recovery_codes(5),
    )
    txt, pdf = write_recovery_kit(kit, tmp_path)
    assert txt.exists()
    content = txt.read_text()
    assert "p@ssw0rd" in content
    assert "admin" in content
    assert "p@ssw0rd" not in str(list(tmp_path.glob("*.pdf")))


# --- Access review ---

@pytest.mark.django_db
def test_start_review(db, su, target):
    RoleAssignment.objects.create(
        user=target, role="viewer", scope_type="global", scope_id=0,
    )
    run = start_access_review(triggered_by=su)
    assert run.total_assignments >= 2
    assert run.pending == run.total_assignments
    assert AccessReviewItem.objects.filter(run=run).count() == run.total_assignments


@pytest.mark.django_db
def test_confirm_review_item(db, su, target):
    RoleAssignment.objects.create(
        user=target, role="viewer", scope_type="global", scope_id=0,
    )
    run = start_access_review(triggered_by=su)
    item = run.items.first()
    confirm_review_item(item, by_user=su)
    item.refresh_from_db()
    assert item.status == "confirmed"
    run.refresh_from_db()
    assert run.confirmed == 1


@pytest.mark.django_db
def test_revoke_review_item(db, su, target):
    ra = RoleAssignment.objects.create(
        user=target, role="viewer", scope_type="global", scope_id=0,
    )
    run = start_access_review(triggered_by=su)
    item = run.items.filter(assignment=ra).first()
    revoke_review_item(item, by_user=su, comment="no longer needed")

    ra.refresh_from_db()
    assert ra.revoked_at is not None


@pytest.mark.django_db
def test_expire_overdue(db, su, target):
    RoleAssignment.objects.create(
        user=target, role="viewer", scope_type="global", scope_id=0,
    )
    run = start_access_review(triggered_by=su, due_in_days=0)
    # сдвинем due_by в прошлое
    AccessReviewItem.objects.filter(run=run).update(
        due_by=timezone.now() - timezone.timedelta(days=1),
    )
    n = expire_overdue_review_items()
    assert n >= 1


# --- UI ---

@pytest.mark.django_db
def test_break_glass_page_requires_supervisor(db, target):
    c = Client()
    c.force_login(target)
    r = c.get("/access/break-glass/")
    assert r.status_code == 403


@pytest.mark.django_db
def test_break_glass_page_ok(db, su):
    ensure_break_glass_account(created_by=su)
    c = Client()
    c.force_login(su)
    r = c.get("/access/break-glass/")
    assert r.status_code == 200


@pytest.mark.django_db
def test_break_glass_refused_when_supervisor_active(db, su):
    """Если SUPERVISOR активен за 24 ч — включать нельзя."""
    from django.utils import timezone

    from apps.access.models import UserActivity

    ensure_break_glass_account(created_by=su)
    UserActivity.objects.update_or_create(
        user=su,
        defaults={"last_activity_at": timezone.now()},
    )

    with pytest.raises(PermissionError, match="активные SUPERVISOR"):
        enable_break_glass(by_user=su, reason="test")


@pytest.mark.django_db
def test_break_glass_force_bypasses_check(db, su):
    from django.utils import timezone

    from apps.access.models import UserActivity

    user, _ = ensure_break_glass_account(created_by=su)
    UserActivity.objects.update_or_create(
        user=su,
        defaults={"last_activity_at": timezone.now()},
    )

    # с force — не падает
    enable_break_glass(by_user=su, reason="emergency", force=True)
    user.refresh_from_db()
    assert user.is_active


@pytest.mark.django_db
def test_break_glass_no_live_supervisors(db, su):
    """Если SUPERVISOR молчит — включаем без force."""
    from django.utils import timezone

    from apps.access.models import UserActivity

    user, _ = ensure_break_glass_account(created_by=su)
    UserActivity.objects.update_or_create(
        user=su,
        defaults={"last_activity_at":
                  timezone.now() - timezone.timedelta(hours=48)},
    )

    enable_break_glass(by_user=su, reason="ok")
    user.refresh_from_db()
    assert user.is_active


@pytest.mark.django_db
def test_break_glass_login_sets_aal3(db):
    """Логин break-glass выставляет AAL3 в сессии."""
    from django.utils import timezone

    from apps.access.models import BreakGlassAccount

    user, password = ensure_break_glass_account(created_by=None)
    acc = BreakGlassAccount.get()
    acc.enable(by_user=None, reason="test")

    c = Client()
    # allauth login
    r = c.post("/accounts/login/", {
        "login": "break-glass",
        "password": password,
    })
    assert r.status_code == 302
    assert c.session.get("psi_aal") == "aal3"


@pytest.mark.django_db
def test_break_glass_page_readonly(db, su):
    """UI показывает состояние, но нет форм управления."""
    ensure_break_glass_account(created_by=su)
    c = Client()
    c.force_login(su)
    r = c.get("/access/break-glass/")
    assert r.status_code == 200
    body = r.content.decode()
    # нет форм с enable/disable
    assert 'action="enable"' not in body
    assert 'action="disable"' not in body
    # есть инструкция
    assert "manage.py break_glass enable" in body


@pytest.mark.django_db
def test_break_glass_page_denied_for_viewer(db):
    from apps.access.models import RoleAssignment
    u = User.objects.create_user("viewer")
    RoleAssignment.objects.create(
        user=u, role="viewer", scope_type="global", scope_id=0,
    )
    c = Client()
    c.force_login(u)
    r = c.get("/access/break-glass/")
    assert r.status_code == 403


@pytest.mark.django_db
def test_break_glass_force_audited(db, su):
    from django.utils import timezone

    from apps.access.models import UserActivity

    ensure_break_glass_account(created_by=su)
    UserActivity.objects.update_or_create(
        user=su,
        defaults={"last_activity_at": timezone.now()},
    )
    enable_break_glass(by_user=su, reason="emergency", force=True)

    log = AuthAuditLog.objects.filter(
        event=AuthAuditLog.Event.BREAK_GLASS_ENABLED,
        success=True,
    ).last()
    assert log is not None
    assert log.detail.get("force") is True