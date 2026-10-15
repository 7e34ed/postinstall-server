"""Sealing и верификация хеш-цепочки."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.db import connection, transaction
from django.utils import timezone
from loguru import logger

from apps.core.audit_chain import canonical_payload, compute_chain_hash

from .crypto import sign, verify
from .models import AuditSeal, AuditSigningKey, AuditVerifyRun
from .sources import get_lock_key, get_source_model


@dataclass
class SealResult:
    source: str
    first_id: int | None
    last_id: int | None
    count: int


@transaction.atomic
def seal_source(source: str) -> SealResult | None:
    """Запечатать новые записи для указанного source.

    Возвращает None, если новых записей нет.

    Защита от гонки:
      * Postgres advisory transaction lock на source;
      * unique_together (source, last_id) в модели как fallback.
    """
    # Advisory lock на конкретный source (не блокирует другие источники)
    lock_key = get_lock_key(source)
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", [lock_key])

    Model = get_source_model(source)
    last_seal = (
        AuditSeal.objects
        .select_for_update(skip_locked=False)
        .filter(source=source)
        .order_by("-last_id")
        .first()
    )
    start_id = (last_seal.last_id + 1) if last_seal else 0

    qs = Model.objects.filter(id__gte=start_id).order_by("id")
    first = qs.first()
    if first is None:
        return None
    last = qs.order_by("-id").first()
    count = qs.count()

    key = AuditSigningKey.get_active()
    seal = AuditSeal(
        source=source,
        first_id=first.pk,
        last_id=last.pk,
        count=count,
        chain_hash=last.chain_hash,
        key=key,
    )
    seal.signature = sign(key.privkey_pem, seal.canonical_payload())
    seal.save()

    logger.info(
        f"audit: sealed {source} [{first.pk}..{last.pk}] ({count})"
    )
    return SealResult(
        source=source, first_id=first.pk,
        last_id=last.pk, count=count,
    )


@dataclass
class VerifyResult:
    source: str
    status: str            # ok | failed | partial
    checked_records: int
    checked_seals: int
    first_broken_id: int | None
    details: dict[str, Any]


def _verify_chain(Model, from_id: int = 0,
                   max_records: int | None = None) -> tuple[int, int | None, dict]:
    """Проверить цепочку записей.

    Возвращает (checked, first_broken_id, details).
    """
    qs = Model.objects.filter(id__gte=from_id).order_by("id")
    if max_records:
        qs = qs[:max_records]

    prev_hash = ""
    checked = 0
    first_broken: int | None = None
    details: dict[str, Any] = {"breaks": []}

    for row in qs.iterator():
        expected = compute_chain_hash(prev_hash, canonical_payload(row._chain_payload()))
        if row.prev_hash != prev_hash or row.chain_hash != expected:
            if first_broken is None:
                first_broken = row.pk
            details["breaks"].append({
                "id": row.pk,
                "expected_prev": prev_hash,
                "actual_prev": row.prev_hash,
                "expected_hash": expected,
                "actual_hash": row.chain_hash,
            })
            if len(details["breaks"]) >= 20:
                break
        prev_hash = row.chain_hash
        checked += 1

    return checked, first_broken, details


def _verify_seals(source: str) -> tuple[int, int | None, dict]:
    """Проверить подписи seal'ов и непрерывность диапазонов."""
    seals = list(AuditSeal.objects.filter(source=source).order_by("first_id"))
    details: dict[str, Any] = {"bad_seals": []}
    prev_last = -1
    first_broken: int | None = None

    for seal in seals:
        # непрерывность
        if seal.first_id != prev_last + 1 and prev_last != -1:
            details["bad_seals"].append({
                "id": seal.pk, "reason": "gap",
                "expected_first_id": prev_last + 1,
                "actual_first_id": seal.first_id,
            })
            if first_broken is None:
                first_broken = seal.first_id

        # подпись
        if not verify(seal.key.pubkey_pem, seal.canonical_payload(),
                       seal.signature):
            details["bad_seals"].append({
                "id": seal.pk, "reason": "signature",
            })
            if first_broken is None:
                first_broken = seal.first_id

        # chain_hash seal'а должен совпадать с chain_hash последней записи
        Model = get_source_model(source)
        last = Model.objects.filter(pk=seal.last_id).only("chain_hash").first()
        if last is None or last.chain_hash != seal.chain_hash:
            details["bad_seals"].append({
                "id": seal.pk, "reason": "chain_hash_mismatch",
            })
            if first_broken is None:
                first_broken = seal.first_id

        prev_last = seal.last_id

    return len(seals), first_broken, details


def verify_source(source: str, *, from_id: int = 0,
                   max_records: int | None = None) -> VerifyResult:
    """Полная верификация source: записи + seal'ы."""
    Model = get_source_model(source)

    records_checked, records_broken, records_details = _verify_chain(
        Model, from_id=from_id, max_records=max_records,
    )
    seals_checked, seals_broken, seals_details = _verify_seals(source)

    first_broken = records_broken or seals_broken

    if first_broken is None:
        status = AuditVerifyRun.Status.OK
    elif records_broken is not None:
        status = AuditVerifyRun.Status.FAILED
    else:
        status = AuditVerifyRun.Status.PARTIAL

    details = {
        "records": records_details,
        "seals": seals_details,
    }

    run = AuditVerifyRun.objects.create(
        source=source,
        status=status,
        checked_records=records_checked,
        checked_seals=seals_checked,
        first_broken_id=first_broken,
        details=details,
        finished_at=timezone.now(),
    )

    if status == AuditVerifyRun.Status.OK:
        logger.info(
            f"audit: verified {source} OK "
            f"({records_checked} records, {seals_checked} seals)"
        )
    else:
        logger.error(
            f"audit: VERIFY FAILED {source} at id={first_broken} "
            f"(records={records_checked}, seals={seals_checked})"
        )

    return VerifyResult(
        source=source, status=status,
        checked_records=records_checked,
        checked_seals=seals_checked,
        first_broken_id=first_broken,
        details=details,
    )


def seal_all() -> list[SealResult]:
    """Запечатать оба source'а. Для celery."""
    results = []
    for source in AuditSeal.Source.values:
        r = seal_source(source)
        if r is not None:
            results.append(r)
    return results


def verify_all(*, max_records: int | None = None) -> list[VerifyResult]:
    results = []
    for source in AuditSeal.Source.values:
        results.append(verify_source(source, max_records=max_records))
    return results