import base64

import pytest
from django.test import override_settings

from apps.secrets import blob as b
from apps.secrets.backends import get_backend
from apps.secrets.backends.local import LocalBackend
from apps.secrets.migration import migrate
from apps.secrets.models import SecretsMigration, ServerKey
from apps.secrets.runtime import runtime


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


# --- in-memory backend для target (заглушка) ---

class InMemoryBackend(LocalBackend):
    """Тестовый backend: хранит секреты в своём dict."""
    name = "test_target"

    def __init__(self):
        self._store: dict[str, dict] = {}

    def get(self, path, key):
        from apps.secrets.backends.base import SecretNotFound
        if path not in self._store or key not in self._store[path]:
            raise SecretNotFound(f"{path}:{key}")
        return self._store[path][key]

    def set(self, path, key, value):
        self._store.setdefault(path, {})[key] = value

    def delete(self, path):
        self._store.pop(path, None)

    def exists(self, path):
        return path in self._store

    def iter_secrets(self, prefix=""):
        for p, kv in self._store.items():
            if prefix and not p.startswith(prefix):
                continue
            for k, v in kv.items():
                yield p, k, v


@pytest.fixture
def patched_backends(monkeypatch, unsealed):
    """Регистрируем InMemoryBackend под именем 'test_target'."""
    from apps.secrets import backends
    backends.BACKEND_CLASSES["test_target"] = InMemoryBackend
    # очищаем на случай повторного использования
    InMemoryBackend._store = {}
    yield
    backends.BACKEND_CLASSES.pop("test_target", None)


def test_dry_run_does_not_write(patched_backends, unsealed):
    runtime.set("a/b/c", "value", "x")
    runtime.persist()

    m = migrate(source="local", target="test_target", dry_run=True)
    assert m.status == SecretsMigration.Status.DRY_RUN
    assert m.done >= 1
    # в target ничего не появилось
    tgt = InMemoryBackend()
    assert not tgt._store


def test_migrate_simple(patched_backends, unsealed):
    runtime.set("a/b/c", "value", "hello")
    runtime.set("d/e/f", "password", "world")
    runtime.persist()

    m = migrate(source="local", target="test_target")
    assert m.status == SecretsMigration.Status.SUCCESS
    assert m.done == 2
    assert m.skipped == 0
    assert m.failed == 0

    tgt = InMemoryBackend()
    assert tgt._store["a/b/c"]["value"] == "hello"
    assert tgt._store["d/e/f"]["password"] == "world"


def test_migrate_skips_existing_without_overwrite(patched_backends, unsealed):
    runtime.set("a/b", "value", "v1")
    runtime.persist()

    # первый прогон — записывает
    migrate(source="local", target="test_target")

    # второй — пропускает
    m = migrate(source="local", target="test_target")
    assert m.skipped == 1
    assert m.done == 0


def test_migrate_overwrite(patched_backends, unsealed):
    runtime.set("a/b", "value", "old")
    runtime.persist()
    migrate(source="local", target="test_target")

    runtime.set("a/b", "value", "new")
    runtime.persist()

    m = migrate(source="local", target="test_target", overwrite=True)
    assert m.done == 1
    tgt = InMemoryBackend()
    assert tgt._store["a/b"]["value"] == "new"


def test_migrate_with_prefix(patched_backends, unsealed):
    runtime.set("keep/1", "value", "x")
    runtime.set("keep/2", "value", "y")
    runtime.set("other/3", "value", "z")
    runtime.persist()

    m = migrate(source="local", target="test_target", prefix="keep/")
    assert m.total == 2
    assert m.done == 2
    tgt = InMemoryBackend()
    assert "keep/1" in tgt._store
    assert "keep/2" in tgt._store
    assert "other/3" not in tgt._store


def test_migrate_activate_target(patched_backends, unsealed):
    runtime.set("a/b", "value", "x")
    runtime.persist()

    m = migrate(source="local", target="test_target", activate_target=True)
    assert m.status == SecretsMigration.Status.SUCCESS
    assert runtime.get_active_backend() == "test_target"


def test_migrate_source_equals_target_rejected(patched_backends, unsealed):
    with pytest.raises(ValueError, match="совпадают"):
        migrate(source="local", target="local")


def test_migrate_sealed_rejected(db):
    with pytest.raises(Exception):
        migrate(source="local", target="test_target")


def test_resume(patched_backends, unsealed, monkeypatch):
    """Симулируем прерывание и resume."""
    runtime.set("a/1", "value", "v1")
    runtime.set("a/2", "value", "v2")
    runtime.set("a/3", "value", "v3")
    runtime.persist()

    # подменяем set на target, чтобы имитировать KeyboardInterrupt на 2-й записи
    call_count = {"n": 0}
    original_set = InMemoryBackend.set

    def fake_set(self, path, key, value):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise KeyboardInterrupt()
        original_set(self, path, key, value)

    monkeypatch.setattr(InMemoryBackend, "set", fake_set)

    m = migrate(source="local", target="test_target")
    assert m.status == SecretsMigration.Status.CANCELLED
    assert m.done == 1
    assert m.last_path

    # восстанавливаем set и продолжаем
    monkeypatch.setattr(InMemoryBackend, "set", original_set)
    m2 = migrate(
        source="local", target="test_target",
        resume_id=m.id,
    )
    assert m2.status == SecretsMigration.Status.SUCCESS
    assert m2.done == 2  # остальные 2 записи