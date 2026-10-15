"""Создать break-glass-учётку и recovery kit.

Использование:
    manage.py bootstrap_break_glass [--out /path/to/kit]

По умолчанию кладёт kit в /var/lib/postinstall/recovery/.
"""
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.access.models import BreakGlassAccount
from apps.access.recovery_kit import (
    RecoveryKitData,
    generate_recovery_codes,
    write_recovery_kit,
)
from apps.access.services import ensure_break_glass_account

DEFAULT_OUT = Path("/var/lib/postinstall/recovery")


class Command(BaseCommand):
    help = "Создать break-glass-учётку и recovery kit"

    def add_arguments(self, parser):
        parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                            help=f"Каталог для recovery kit (по умолчанию {DEFAULT_OUT})")
        parser.add_argument("--force", action="store_true",
                            help="Пересоздать, даже если break-glass уже есть")

    def handle(self, *args, **opts):
        if BreakGlassAccount.objects.exists() and not opts["force"]:
            raise CommandError(
                "Break-glass уже существует. Используйте --force для пересоздания."
            )

        if opts["force"]:
            BreakGlassAccount.objects.all().delete()

        user, password = ensure_break_glass_account(created_by=None)
        if not password:
            # уже был — не показываем пароль
            self.stdout.write(self.style.WARNING(
                "Break-glass уже существовал, пароль не изменён."
            ))
            return

        recovery_codes = generate_recovery_codes(10)
        kit = RecoveryKitData(
            username=user.username,
            password=password,
            recovery_codes=recovery_codes,
            notes=(
                "Это аварийный доступ.\n\n"
                "1. Сохраните файл в защищённом месте.\n"
                "2. При необходимости — включите break-glass через UI "
                "SUPERVISOR'ом с AAL3.\n"
                "3. По умолчанию учётка неактивна; включение "
                "автоматически выключается через 24 ч.\n"
                "4. Все входы break-glass пишутся в аудит и уведомляют "
                "всех SUPERVISOR'ов."
            ),
        )
        txt, pdf = write_recovery_kit(kit, opts["out"])
        self.stdout.write(self.style.SUCCESS(
            f"Recovery kit создан: {txt}"
            + (f", {pdf}" if pdf else " (PDF не сгенерирован, "
               "установите reportlab)")
        ))