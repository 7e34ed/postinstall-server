"""Хеш-цепочка для append-only логов.

Каждая запись содержит:
  * prev_hash  — chain_hash предыдущей записи ("" для первой);
  * chain_hash — sha256(prev_hash || canonical_payload).

Правила:
  * запись только добавляется — update/delete запрещены;
  * save() вычисляет хеш под advisory lock (Postgres);
  * bulk update/delete через queryset запрещены на уровне менеджера.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, ClassVar

from django.db import connection, models, transaction
from django.utils import timezone


def compute_chain_hash(prev_hash: str, payload: str) -> str:
    h = hashlib.sha256()
    h.update((prev_hash or "").encode("utf-8"))
    h.update(b"|")
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


def canonical_payload(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise RuntimeError(
            "append-only: bulk update запрещён. "
            "Используйте прямую вставку новых записей."
        )

    def delete(self):
        raise RuntimeError(
            "append-only: bulk delete запрещён."
        )


class AppendOnlyManager(models.Manager.from_queryset(AppendOnlyQuerySet)):
    pass


class ChainedLogModel(models.Model):
    ADVISORY_LOCK_KEY: ClassVar[int] = 0

    prev_hash = models.CharField(
        max_length=64, blank=True, default="", editable=False,
    )
    chain_hash = models.CharField(
        max_length=64, blank=True, default="", db_index=True, editable=False,
    )

    class Meta:
        abstract = True
    
    def save(self, *args, **kwargs):
        # Запрет обновления существующей записи
        if self.pk is not None and not kwargs.pop("_initial_save", False):
            # Миграционный путь помечается _initial_save=True
            raise RuntimeError(
                f"{self.__class__.__name__}: append-only, "
                f"обновление записи запрещено."
            )

        # Только для создания:
        with transaction.atomic():
            if self.ADVISORY_LOCK_KEY:
                with connection.cursor() as cur:
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(%s)",
                        [self.ADVISORY_LOCK_KEY],
                    )

            last = (
                self.__class__.objects
                .order_by("-pk")
                .only("chain_hash")
                .first()
            )
            self.prev_hash = last.chain_hash if last else ""
            payload = canonical_payload(self._chain_payload())
            self.chain_hash = compute_chain_hash(self.prev_hash, payload)

            kwargs["force_insert"] = True
            super().save(*args, **kwargs)

    def _chain_payload(self) -> dict:
            raise NotImplementedError


    def delete(self, *args, **kwargs):
        raise RuntimeError(
            f"{self.__class__.__name__}: append-only, удаление запрещено."
        )