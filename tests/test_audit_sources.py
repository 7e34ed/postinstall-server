import pytest

from apps.audit.models import AuditSeal
from apps.audit.sources import (
    SOURCE_LOCK_KEYS,
    SOURCE_MODELS,
    UnknownAuditSource,
    all_sources,
    get_lock_key,
    get_source_model,
    is_valid_source,
)


def test_source_models_cover_enum():
    enum_values = set(AuditSeal.Source.values)
    assert set(SOURCE_MODELS.keys()) == enum_values
    assert set(SOURCE_LOCK_KEYS.keys()) == enum_values


def test_lock_keys_unique():
    keys = list(SOURCE_LOCK_KEYS.values())
    assert len(keys) == len(set(keys))


def test_get_source_model_ok():
    M = get_source_model("audit_log")
    assert M.__name__ == "AuditLog"

    M = get_source_model("auth_audit_log")
    assert M.__name__ == "AuthAuditLog"


def test_get_source_model_unknown():
    with pytest.raises(UnknownAuditSource):
        get_source_model("bogus")


def test_all_sources_matches_enum():
    assert set(all_sources()) == set(AuditSeal.Source.values)


def test_is_valid_source():
    assert is_valid_source("audit_log")
    assert not is_valid_source("nope")