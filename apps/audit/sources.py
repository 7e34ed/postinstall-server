"""Единый резолвер моделей-источников аудита.

Используется во всех модулях audit (sealing, export, verify).
Гарантирует согласованность между source-именами и моделями.
"""

from __future__ import annotations

from typing import ClassVar

from django.apps import apps as django_apps

from .models import AuditSeal


class UnknownAuditSource(ValueError):
    pass


# Канонический маппинг source → (app_label, model_name)
SOURCE_MODELS: dict[str, tuple[str, str]] = {
    AuditSeal.Source.AUDIT_LOG.value: ("core", "AuditLog"),
    AuditSeal.Source.AUTH_AUDIT_LOG.value: ("access", "AuthAuditLog"),
}


# Advisory lock key для каждого source.
# Уникальные значения, чтобы seal разных source не блокировали друг друга.
SOURCE_LOCK_KEYS: dict[str, int] = {
    AuditSeal.Source.AUDIT_LOG.value: 0x4155_5345_414C_01,      # "AUSEAL" + 1
    AuditSeal.Source.AUTH_AUDIT_LOG.value: 0x4155_5345_414C_02,  # "AUSEAL" + 2
}


def get_source_model(source: str):
    """Вернуть модель для source. Бросает UnknownAuditSource."""
    if source not in SOURCE_MODELS:
        raise UnknownAuditSource(
            f"неизвестный source: {source!r}. "
            f"Допустимые: {list(SOURCE_MODELS)}"
        )
    app_label, model_name = SOURCE_MODELS[source]
    return django_apps.get_model(app_label, model_name)


def get_lock_key(source: str) -> int:
    """Advisory lock key для source."""
    if source not in SOURCE_LOCK_KEYS:
        raise UnknownAuditSource(f"нет lock key для source {source!r}")
    return SOURCE_LOCK_KEYS[source]


def all_sources() -> list[str]:
    """Список всех source'ов."""
    return list(SOURCE_MODELS.keys())


def is_valid_source(source: str) -> bool:
    return source in SOURCE_MODELS