"""Управление break-glass.

    manage.py break_glass status
    manage.py break_glass enable --reason "..." [--force] [--hours N]
    manage.py break_glass disable
    manage.py break_glass reset-kit [--out DIR]

Включение/выключение — только с физического доступа к серверу.
UI (custom) показывает состояние, но не управляет.
"""
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.access.models import BreakGlassAccount
from apps.access.recovery_kit import (
    RecoveryKitData,
    generate_recovery_codes,
    write_recovery_kit,
)
from apps.access.services import (
    can_enable_break_glass,
    disable_break_glass,
    enable_break_glass,
    ensure_break_glass_account,
)

DEFAULT_KIT_DIR = Path("/var/lib/postinstall/recovery")


class Command(BaseCommand):
    help = "Break-glass: статус, включение, выключение, сброс kit"

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="cmd", required=True)

        sub.add_parser("status", help="Показать состояние")

        en = sub.add_parser("enable", help="Включить")
        en.add_argument("--reason", required=True,
                        help="Причина включения (обязательно)")
        en.add_argument("--force", action="store_true",
                        help="Обход проверки «живых» SUPERVISOR'ов")
        en.add_argument("--hours", type=int, default=None,
                        help="Переопределить auto-disable (часов)")
        en.add_argument("--check-hours", type=int, default=24,
                        help="Окно проверки активности SUPERVISOR'ов")

        sub.add_parser("disable", help="Выключить")

        kit = sub.add_parser("reset-kit", help="Пересоздать пароль и kit")
        kit.add_argument("--out", type=Path, default=DEFAULT_KIT_DIR)

    def handle(self, *args, **opts):
        cmd = opts["cmd"]
        handler = {
            "status": self._status,
            "enable": self._enable,
            "disable": self._disable,
            "reset-kit": self._reset_kit,
        }[cmd]
        handler(**opts)

    # --- status ---

    def _status(self, **_):
        acc = BreakGlassAccount.get()
        if acc is None:
            self.stdout.write("Break-glass не создан.")
            self.stdout.write(
                "Создайте: manage.py bootstrap_break_glass"
            )
            return

        active = acc.is_currently_active()
        self.stdout.write(f"Логин:           {acc.user.username}")
        self.stdout.write(f"Активен:         {'ДА' if active else 'нет'}")
        self.stdout.write(
            f"Авто-выключение: через {acc.auto_disable_after_hours} ч"
        )
        self.stdout.write(
            f"Включён:         {acc.enabled_at or '—'}"
        )
        self.stdout.write(
            f"Кем:             "
            f"{acc.enabled_by.username if acc.enabled_by else '—'}"
        )
        self.stdout.write(f"Причина:         {acc.enabled_reason or '—'}")
        self.stdout.write(f"Всего входов:    {acc.use_count}")
        self.stdout.write(f"Последний вход:  {acc.last_used_at or '—'}")

        if not active:
            ok, why = can_enable_break_glass()
            self.stdout.write("")
            if ok:
                self.stdout.write(self.style.SUCCESS(
                    "Можно включить: да"
                ))
            else:
                self.stdout.write(self.style.WARNING(
                    f"Можно включить: НЕТ — {why}"
                ))

    # --- enable ---

    def _enable(self, reason, force, hours, check_hours, **_):
        acc = BreakGlassAccount.get()
        if acc is None:
            raise CommandError(
                "Break-glass не создан. "
                "Выполните: manage.py bootstrap_break_glass"
            )
        if acc.is_currently_active():
            raise CommandError("Break-glass уже активен.")

        if force:
            self.stdout.write(self.style.WARNING(
                "Флаг --force: проверка «живых» SUPERVISOR'ов будет "
                "проигнорирована. Событие попадёт в аудит как force=true."
            ))

        try:
            enable_break_glass(
                by_user=None,
                reason=reason,
                force=force,
                check_hours=check_hours,
            )
        except PermissionError as exc:
            raise CommandError(str(exc))  # noqa: B904

        if hours is not None:
            acc.refresh_from_db()
            acc.auto_disable_after_hours = hours
            acc.save(update_fields=["auto_disable_after_hours"])

        acc.refresh_from_db()
        self.stdout.write(self.style.SUCCESS(
            f"Break-glass включён на {acc.auto_disable_after_hours} ч. "
            "Все SUPERVISOR'ы уведомлены."
        ))

    # --- disable ---

    def _disable(self, **_):
        try:
            disable_break_glass(by_user=None)
        except Exception as exc:
            raise CommandError(str(exc))  # noqa: B904
        self.stdout.write(self.style.SUCCESS("Break-glass выключен."))

    # --- reset-kit ---

    def _reset_kit(self, out: Path, **_):
        confirm = input(
            'Сбросить пароль break-glass? Напишите "reset": '
        ).strip()
        if confirm != "reset":
            raise CommandError("Отменено")

        BreakGlassAccount.objects.all().delete()
        user, password = ensure_break_glass_account(created_by=None)
        codes = generate_recovery_codes(10)
        kit = RecoveryKitData(
            username=user.username,
            password=password,
            recovery_codes=codes,
            notes=(
                "Break-glass для postinstall-server.\n"
                "Сохраните в физическом сейфе.\n"
                "Включение/выключение — только через manage.py."
            ),
        )
        txt, pdf = write_recovery_kit(kit, out)
        self.stdout.write(self.style.SUCCESS(
            f"Recovery kit: {txt}"
            + (f", {pdf}" if pdf else " (PDF не сгенерирован)")
        ))