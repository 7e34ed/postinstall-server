
import os
from pathlib import Path

import pytest
from django.test import override_settings

from apps.secrets.backends.base import SecretBackendError, SecretNotFound
from apps.secrets.keepass_helpers import (
    KeepassError,
    KeepassParams,
    atomic_save,
    snapshot,
    validate_path,
)


@pytest.fixture
def kdbx_path(tmp_path):
    return tmp_path / "test.kdbx"


@pytest.fixture
def params(kdbx_path):
    from pykeepass import create_database

    create_database(str(kdbx_path), password="test-master")
    return KeepassParams(
        kdbx_path=kdbx_path,
        password="test-master",
        backup_retention=3,
    )


@pytest.fixture
def backend(params, monkeypatch, db):
    """Создаём backend, минуя runtime."""
    from apps.secrets.backends.keepass import KeepassBackend
    
    b = KeepassBackend.__new__(KeepassBackend)
    b.params = params
    return b


# --- validate_path ---

def test_validate_path_relative():
    with pytest.raises(KeepassError, match="абсолютным"):
        validate_path(Path("relative.kdbx"), allow_missing=True)


def test_validate_path_tmp():
    with pytest.raises(KeepassError, match="/tmp"):
        validate_path(Path("/tmp/secrets.kdbx"), allow_missing=True)


def test_validate_path_proc():
    with pytest.raises(KeepassError, match="запрещённом"):
        validate_path(Path("/proc/secrets.kdbx"), allow_missing=True)


@pytest.mark.django_db
def test_validate_path_in_base_dir(tmp_path, settings):
    settings.BASE_DIR = tmp_path
    with pytest.raises(KeepassError, match="webroot"):
        validate_path(tmp_path / "secrets.kdbx", allow_missing=True)


@pytest.mark.django_db
def test_validate_path_ok(tmp_path):
    # tmp_path от pytest лежит где-то в /tmp — обойдём проверку
    # но у нас запрет на /tmp, так что используем /var/tmp
    # На практике проще взять домашний каталог
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="keepass-test-", dir="/var/tmp"))
    try:
        validate_path(d / "secrets.kdbx", allow_missing=True)
    finally:
        d.rmdir()


# --- Basic CRUD ---

def test_set_get(backend):
    backend.set("domains/example.local/domain_password", "password", "s3cret")
    assert backend.get("domains/example.local/domain_password",
                       "password") == "s3cret"


def test_set_get_custom_key(backend):
    backend.set("a/b/entry", "value", "custom")
    assert backend.get("a/b/entry", "value") == "custom"


def test_get_missing_path(backend):
    with pytest.raises(SecretNotFound):
        backend.get("nonexistent/path", "password")


def test_get_missing_key(backend):
    backend.set("a/b/entry", "password", "x")
    with pytest.raises(SecretNotFound):
        backend.get("a/b/entry", "nonexistent")


def test_update(backend):
    backend.set("a/b/entry", "password", "v1")
    backend.set("a/b/entry", "password", "v2")
    assert backend.get("a/b/entry", "password") == "v2"


def test_delete(backend):
    backend.set("a/b/entry", "password", "x")
    assert backend.exists("a/b/entry")
    backend.delete("a/b/entry")
    assert not backend.exists("a/b/entry")


def test_delete_missing(backend):
    # не должно падать
    backend.delete("a/b/missing")


def test_exists(backend):
    assert not backend.exists("a/b/entry")
    backend.set("a/b/entry", "password", "x")
    assert backend.exists("a/b/entry")


def test_multiple_groups(backend):
    backend.set("g1/sub1/entry1", "password", "p1")
    backend.set("g1/sub2/entry2", "password", "p2")
    backend.set("g2/entry3", "password", "p3")
    assert backend.get("g1/sub1/entry1", "password") == "p1"
    assert backend.get("g1/sub2/entry2", "password") == "p2"
    assert backend.get("g2/entry3", "password") == "p3"


def test_multiple_properties(backend):
    backend.set("a/b/entry", "password", "p")
    backend.set("a/b/entry", "username", "u")
    backend.set("a/b/entry", "url", "https://example.com")
    backend.set("a/b/entry", "notes", "note")
    backend.set("a/b/entry", "custom1", "c1")

    assert backend.get("a/b/entry", "password") == "p"
    assert backend.get("a/b/entry", "username") == "u"
    assert backend.get("a/b/entry", "url") == "https://example.com"
    assert backend.get("a/b/entry", "notes") == "note"
    assert backend.get("a/b/entry", "custom1") == "c1"


def test_persistence_across_reload(backend, kdbx_path):
    backend.set("a/b/entry", "password", "x")

    # сбрасываем кэш и перечитываем
    from apps.secrets.keepass_helpers import invalidate_cache
    invalidate_cache()

    assert backend.get("a/b/entry", "password") == "x"


def test_health(backend):
    h = backend.health()
    assert h["status"] == "ok"
    assert h["path"] == str(backend.params.kdbx_path)
    assert h["entries"] >= 0


# --- Snapshots ---

def test_snapshot_created(backend):
    backend.set("a/b/entry", "password", "v1")
    backend.set("a/b/entry", "password", "v2")

    backup_dir = backend.params.effective_backup_dir
    assert backup_dir.exists()
    snapshots = list(backup_dir.glob("*.kdbx"))
    assert len(snapshots) >= 1


def test_snapshot_retention(backend):
    # retention=3, делаем 6 записей — должно остаться <=3 снапшотов
    for i in range(6):
        backend.set("a/b/entry", "password", f"v{i}")
        import time; time.sleep(0.01)

    backup_dir = backend.params.effective_backup_dir
    snapshots = list(backup_dir.glob("*.kdbx"))
    assert len(snapshots) <= 3


# --- Неверный пароль ---

def test_wrong_password(kdbx_path):
    from pykeepass import create_database

    from apps.secrets.backends.keepass import KeepassBackend
    create_database(str(kdbx_path), password="correct")

    b = KeepassBackend.__new__(KeepassBackend)
    b.params = KeepassParams(kdbx_path=kdbx_path, password="wrong")

    with pytest.raises(KeepassError, match="не удалось открыть"):
        b.get("a/b/c", "password")


# --- Composite key ---

def test_composite_key(tmp_path):
    from pykeepass import create_database

    from apps.secrets.backends.keepass import KeepassBackend

    kdbx = tmp_path / "c.kdbx"
    keyfile = tmp_path / "c.key"
    keyfile.write_bytes(os.urandom(32))

    create_database(str(kdbx), password="pw", keyfile=str(keyfile))

    b = KeepassBackend.__new__(KeepassBackend)
    b.params = KeepassParams(
        kdbx_path=kdbx, password="pw", keyfile_path=keyfile,
    )
    b.set("a/b/c", "password", "x")
    assert b.get("a/b/c", "password") == "x"


def test_missing_keyfile_fails(tmp_path):
    from pykeepass import create_database

    from apps.secrets.backends.keepass import KeepassBackend

    kdbx = tmp_path / "c.kdbx"
    keyfile = tmp_path / "c.key"
    keyfile.write_bytes(os.urandom(32))
    create_database(str(kdbx), password="pw", keyfile=str(keyfile))

    b = KeepassBackend.__new__(KeepassBackend)
    b.params = KeepassParams(
        kdbx_path=kdbx, password="pw", keyfile_path=None,  # без keyfile
    )
    with pytest.raises(KeepassError):
        b.get("a/b/c", "password")


# --- Bad path ---

def test_split_path_requires_group(backend):
    with pytest.raises(KeepassError, match="минимум одну группу"):
        backend.set("onlyentry", "password", "x")


@pytest.fixture(autouse=True)
def _drain_snapshots():
    yield
    # не shutdown, а дождаться
    import time

    from apps.secrets.keepass_helpers import shutdown_snapshot_pool
    time.sleep(0.1)   # простое решение для тестов


def test_snapshot_eventually_created(backend):
    backend.set("a/b/entry", "password", "v1")
    backend.set("a/b/entry", "password", "v2")

    import time
    deadline = time.time() + 2.0
    backup_dir = backend.params.effective_backup_dir
    while time.time() < deadline:
        snapshots = list(backup_dir.glob("*.kdbx"))
        if len(snapshots) >= 1:
            return
        time.sleep(0.05)
    pytest.fail("snapshot не появился за 2 секунды")