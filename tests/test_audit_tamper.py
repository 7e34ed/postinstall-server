import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.audit.models import (
    AuditSeal,
    AuditSigningKey,
    AuditVerifyRun,
)
from apps.audit.sealing import (
    seal_all,
    seal_source,
    verify_all,
    verify_source,
)
from apps.core.models import AuditLog

User = get_user_model()


def _mk_log(**overrides):
    """Создать тестовую запись."""
    data = {
        "level": AuditLog.Level.INFO,
        "logger": "test",
        "message": "test message",
    }
    data.update(overrides)
    return AuditLog.objects.create(**data)


# --- Append-only ---

@pytest.mark.django_db
def test_auditlog_create():
    log = _mk_log()
    assert log.pk is not None
    assert log.chain_hash
    assert log.prev_hash == ""   # первая запись


@pytest.mark.django_db
def test_auditlog_update_forbidden():
    log = _mk_log()
    log.message = "changed"
    with pytest.raises(RuntimeError, match="append-only"):
        log.save()


@pytest.mark.django_db
def test_auditlog_delete_forbidden():
    log = _mk_log()
    with pytest.raises(RuntimeError, match="append-only"):
        log.delete()


# --- Chain ---

@pytest.mark.django_db
def test_chain_links():
    a = _mk_log(message="a")
    b = _mk_log(message="b")
    c = _mk_log(message="c")

    assert a.prev_hash == ""
    assert b.prev_hash == a.chain_hash
    assert c.prev_hash == b.chain_hash


@pytest.mark.django_db
def test_chain_verify_ok():
    for i in range(5):
        _mk_log(message=f"msg-{i}")

    r = verify_source("audit_log")
    assert r.status == "ok"
    assert r.checked_records == 5


@pytest.mark.django_db
def test_chain_verify_after_tamper():
    """Прямое изменение chain_hash через update() обнаруживается."""
    logs = [_mk_log(message=f"m{i}") for i in range(3)]

    # Имитируем tamper: меняем chain_hash у средней записи
    AuditLog.objects.filter(pk=logs[1].pk).update(chain_hash="0" * 64)

    r = verify_source("audit_log")
    assert r.status != "ok"
    assert r.first_broken_id in (logs[1].pk, logs[2].pk)


# --- Sealing ---

@pytest.mark.django_db
def test_seal_creates():
    for i in range(3):
        _mk_log(message=f"m{i}")
    result = seal_source("audit_log")
    assert result is not None
    assert result.count == 3

    seal = AuditSeal.objects.get(source="audit_log")
    assert seal.first_id == 1
    assert seal.last_id == 3
    assert seal.signature
    assert seal.key_id is not None


@pytest.mark.django_db
def test_seal_no_new_records():
    for i in range(2):
        _mk_log(message=f"m{i}")
    seal_source("audit_log")
    again = seal_source("audit_log")
    assert again is None   # нечего запечатывать


@pytest.mark.django_db
def test_seal_signature_valid():
    for i in range(2):
        _mk_log(message=f"m{i}")
    seal_source("audit_log")

    seal = AuditSeal.objects.get(source="audit_log")
    from apps.audit.crypto import verify
    assert verify(seal.key.pubkey_pem, seal.canonical_payload(),
                   seal.signature)


@pytest.mark.django_db
def test_seal_signature_invalid_after_tamper():
    for i in range(2):
        _mk_log(message=f"m{i}")
    seal_source("audit_log")

    # Меняем chain_hash у seal — подпись не сойдётся
    AuditSeal.objects.filter(source="audit_log").update(
        chain_hash="0" * 64,
    )
    r = verify_source("audit_log")
    assert r.status != "ok"


@pytest.mark.django_db
def test_verify_detects_seal_gap():
    for i in range(5):
        _mk_log(message=f"m{i}")
    seal_source("audit_log")   # [1..5]
    for i in range(3):
        _mk_log(message=f"extra{i}")
    seal_source("audit_log")   # [6..8]

    # Удаляем второй seal → обнаружится gap
    AuditSeal.objects.filter(source="audit_log").order_by("-last_id").first().delete()
    # создаём seal с "дыркой"
    for i in range(2):
        _mk_log(message=f"more{i}")
    seal_source("audit_log")   # [9..10]

    r = verify_source("audit_log")
    # gap между [1..5] и [9..10]
    assert r.status != "ok"


# --- verify_all / seal_all ---

@pytest.mark.django_db
def test_seal_all(db):
    _mk_log(message="x")
    results = seal_all()
    assert len(results) >= 1


@pytest.mark.django_db
def test_verify_all(db):
    _mk_log(message="x")
    results = verify_all()
    assert all(r.status == "ok" for r in results)


# --- Verify runs ---

@pytest.mark.django_db
def test_verify_creates_run():
    _mk_log(message="x")
    verify_source("audit_log")
    assert AuditVerifyRun.objects.filter(source="audit_log").count() == 1


# --- Export ---

@pytest.mark.django_db
def test_export_to_file(tmp_path):
    from apps.audit.export import export_to_file
    _mk_log(message="a")
    _mk_log(message="b")
    path = tmp_path / "audit.jsonl"
    r = export_to_file(path=path)
    assert r["audit_log"] == 2
    lines = path.read_text().strip().split("\n")
    assert len(lines) == 2

    # повторно — ничего не выгружается
    r2 = export_to_file(path=path)
    assert r2["audit_log"] == 0


# --- AuthAuditLog ---

@pytest.mark.django_db
def test_authauditlog_chain():
    from apps.access.models import AuthAuditLog, log_auth_event
    log_auth_event(AuthAuditLog.Event.LOGIN_SUCCESS)
    log_auth_event(AuthAuditLog.Event.LOGOUT)

    rows = list(AuthAuditLog.objects.order_by("id"))
    assert rows[0].prev_hash == ""
    assert rows[1].prev_hash == rows[0].chain_hash

    r = verify_source("auth_audit_log")
    assert r.status == "ok"
    assert r.checked_records == 2


@pytest.mark.django_db
def test_seal_unique_together(db):
    """Второй seal с тем же last_id не создаётся."""
    from django.db import IntegrityError

    _mk_log(message="a")
    seal_source("audit_log")

    seal = AuditSeal.objects.get(source="audit_log")
    with pytest.raises(IntegrityError):
        AuditSeal.objects.create(
            source=seal.source,
            first_id=seal.first_id,
            last_id=seal.last_id,
            count=seal.count,
            chain_hash=seal.chain_hash,
            key=seal.key,
            signature=seal.signature,
        )