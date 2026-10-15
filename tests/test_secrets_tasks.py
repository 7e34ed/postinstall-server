import base64

import pytest
from django.core.cache import cache

from apps.secrets import blob as b
from apps.secrets.models import ServerKey
from apps.secrets.runtime import runtime
from apps.secrets.tasks import (
    HEALTH_CACHE_KEY, health_check, renew_openbao_token,
    renew_openbao_token_now,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


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
def test_renew_skipped_when_local(unsealed):
    # активный backend — local
    assert runtime.get_active_backend() == "local"
    result = renew_openbao_token_now()
    assert result["status"] == "skipped"
    assert "local" in result["reason"]


@pytest.mark.django_db
def test_renew_skipped_when_sealed(db):
    result = renew_openbao_token_now()
    assert result["status"] == "skipped"
    assert result["reason"] == "sealed"


@pytest.mark.django_db
def test_renew_celery_task(unsealed):
    # то же, что и прямой вызов, но через task
    result = renew_openbao_token.apply().result
    assert result["status"] == "skipped"


@pytest.mark.django_db
def test_health_check_local(unsealed):
    result = health_check.apply().result
    assert result["status"] == "ok"

    cached = cache.get(HEALTH_CACHE_KEY.format(name="local"))
    assert cached is not None
    assert cached["status"] == "ok"


@pytest.mark.django_db
def test_health_check_sealed(db):
    result = health_check.apply().result
    assert result["status"] == "skipped"
    cached = cache.get(HEALTH_CACHE_KEY.format(name="*"))
    assert cached is not None
    assert cached["status"] == "sealed"


@pytest.mark.django_db
def test_health_check_unknown_backend(unsealed):
    result = health_check.apply(args=["nonexistent"]).result
    assert result.get("status") == "error"