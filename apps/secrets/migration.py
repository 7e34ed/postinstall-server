"""Сервис миграции секретов между backend'ами.

Особенности:
  * идемпотентно: если target уже содержит path/key и overwrite=False —
    запись пропускается;
  * прерываемо: при KeyboardInterrupt сохраняется checkpoint
    (last_path/last_key), можно продолжить через --resume <id>;
  * безопасно: сперва dry-run (по умолчанию выключен);
  * опционально переключает активный backend на target после успеха.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timezone

from loguru import logger

from .backends import get_backend
from .backends.base import SecretBackendError, SecretNotFound
from .models import SecretsMigration
from .runtime import SecretsSealed, runtime


@dataclass
class MigrationProgress:
    processed: int
    total: int
    done: int
    skipped: int
    failed: int
    current_path: str = ""
    current_key: str = ""


def _target_has(dst, path: str, key: str) -> bool | None:
    """True/False/None(ошибка)."""
    try:
        dst.get(path, key)
        return True
    except SecretNotFound:
        return False
    except Exception as exc:
        logger.warning(f"migrate: probe {path}:{key} failed: {exc}")
        return None


def migrate(
    *,
    source: str,
    target: str,
    prefix: str = "",
    overwrite: bool = False,
    dry_run: bool = False,
    activate_target: bool = False,
    resume_id=None,
    user=None,
    progress_cb=None,
) -> SecretsMigration:
    """Запустить миграцию.

    progress_cb(progress: MigrationProgress) вызывается после каждой
    обработанной записи. Может быть None.
    """
    if not runtime.is_unsealed():
        raise SecretsSealed("runtime sealed — миграция невозможна")

    if source == target:
        raise ValueError("source и target совпадают")

    # --- создаём или берём запись ---
    if resume_id:
        mig = SecretsMigration.objects.get(pk=resume_id)
        if mig.is_final:
            raise ValueError(f"миграция {mig.id} уже завершена ({mig.status})")
        if mig.source_backend != source or mig.target_backend != target:
            raise ValueError(
                "source/target не совпадают с сохранённой миграцией"
            )
        logger.info(
            f"migrate: resume {mig.id} from "
            f"{mig.last_path}:{mig.last_key} "
            f"({mig.done + mig.skipped + mig.failed}/{mig.total})"
        )
    else:
        mig = SecretsMigration.objects.create(
            source_backend=source,
            target_backend=target,
            prefix=prefix,
            overwrite=overwrite,
            dry_run=dry_run,
            activate_target=activate_target,
            status=(
                SecretsMigration.Status.DRY_RUN if dry_run
                else SecretsMigration.Status.RUNNING
            ),
            created_by=user if user and user.is_authenticated else None,
        )

    # --- backend'ы ---
    try:
        src = get_backend(source)
    except SecretBackendError as exc:
        return _fail(mig, f"source backend: {exc}")
    try:
        dst = get_backend(target)
    except SecretBackendError as exc:
        return _fail(mig, f"target backend: {exc}")

    # --- собираем список всех записей ---
    logger.info(f"migrate: collecting from {source} (prefix={prefix!r})")
    items: list[tuple[str, str, str]] = []
    try:
        for path, key, value in src.iter_secrets(prefix):
            items.append((path, key, value))
    except Exception as exc:
        return _fail(mig, f"iter_secrets: {exc}")

    mig.total = len(items)
    mig.save(update_fields=["total"])
    logger.info(f"migrate: найдено {len(items)} записей")

    # --- определяем стартовую позицию ---
    start_at = 0
    if mig.last_path:
        for i, (path, key, _v) in enumerate(items):
            if path == mig.last_path and key == mig.last_key:
                start_at = i + 1
                break

    # --- проход ---
    try:
        for i in range(start_at, len(items)):
            path, key, value = items[i]

            # probe target
            if not overwrite:
                has = _target_has(dst, path, key)
                if has is True:
                    mig.skipped += 1
                    mig.last_path = path
                    mig.last_key = key
                    _save_checkpoint(mig)
                    _emit_progress(mig, path, key, progress_cb)
                    continue
                if has is None:
                    mig.failed += 1
                    mig.add_detail("probe_error", path, key)
                    mig.last_path = path
                    mig.last_key = key
                    _save_checkpoint(mig)
                    _emit_progress(mig, path, key, progress_cb)
                    continue

            # write
            if not dry_run:
                try:
                    dst.set(path, key, value)
                    mig.done += 1
                except Exception as exc:
                    mig.failed += 1
                    mig.add_detail("write_error", path, key, str(exc)[:300])
                    logger.error(f"migrate: set {path}:{key}: {exc}")
            else:
                mig.done += 1

            mig.last_path = path
            mig.last_key = key
            _save_checkpoint(mig)
            _emit_progress(mig, path, key, progress_cb)

    except KeyboardInterrupt:
        logger.warning(f"migrate: interrupted by user at {mig.last_path}:{mig.last_key}")
        mig.status = SecretsMigration.Status.CANCELLED
        mig.finished_at = datetime.now(UTC)
        mig.save()
        return mig

    # --- финализация ---
    mig.finished_at = datetime.now(UTC)
    if mig.failed == 0 and mig.done + mig.skipped == mig.total:
        mig.status = (
            SecretsMigration.Status.DRY_RUN if dry_run
            else SecretsMigration.Status.SUCCESS
        )
    elif mig.done == 0 and mig.failed > 0:
        mig.status = SecretsMigration.Status.FAILED
    else:
        mig.status = SecretsMigration.Status.PARTIAL
    mig.save()

    logger.info(
        f"migrate: done={mig.done} skipped={mig.skipped} "
        f"failed={mig.failed} status={mig.status}"
    )

    # --- опционально переключить активный backend ---
    if (
        activate_target
        and not dry_run
        and mig.status == SecretsMigration.Status.SUCCESS
    ):
        try:
            runtime.set_active_backend(target)
            runtime.persist()
            logger.info(f"migrate: active backend switched to {target}")
        except Exception as exc:
            logger.error(f"migrate: activate target failed: {exc}")
            mig.error = f"activate target: {exc}"
            mig.save(update_fields=["error"])

    return mig


def _save_checkpoint(mig: SecretsMigration) -> None:
    """Сохранить прогресс раз в 20 записей, чтобы не долбить БД."""
    processed = mig.done + mig.skipped + mig.failed
    if processed % 20 == 0 or processed == mig.total:
        mig.save(update_fields=[
            "done", "skipped", "failed", "details",
            "last_path", "last_key",
        ])


def _emit_progress(mig, path, key, cb) -> None:
    if cb is None:
        return
    try:
        cb(MigrationProgress(
            processed=mig.done + mig.skipped + mig.failed,
            total=mig.total,
            done=mig.done, skipped=mig.skipped, failed=mig.failed,
            current_path=path, current_key=key,
        ))
    except Exception:
        pass


def _fail(mig: SecretsMigration, message: str) -> SecretsMigration:
    logger.error(f"migrate: {message}")
    mig.status = SecretsMigration.Status.FAILED
    mig.error = message[:512]
    mig.finished_at = datetime.now(UTC)
    mig.save()
    return mig


def list_migrations(limit: int = 50) -> list[SecretsMigration]:
    return list(SecretsMigration.objects.all()[:limit])


def get_migration(migration_id) -> SecretsMigration:
    return SecretsMigration.objects.get(pk=migration_id)