"""Bootstrap первого SUPERVISOR'а или восстановление setup-фазы.

Используется в двух сценариях:
1) первичная установка — до входа в UI;
2) аварийный сброс setup-фазы (например, потеряли всех SUPERVISOR'ов).
"""
import os
import sys

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.access.checks import InvariantViolation
from apps.access.models import AuthAuditLog, RoleAssignment, SuperuserBootstrap
from apps.access.roles import Role, ScopeType

User = get_user_model()


class Command(BaseCommand):
    help = "Создать/назначить SUPERVISOR'а (bootstrap / аварийное восстановление)"

    def add_arguments(self, parser):
        parser.add_argument("username", help="Логин пользователя")
        parser.add_argument("--email", default="", help="Email")
        parser.add_argument("--force-setup-reset", action="store_true",
                            help="Сбросить setup-фазу (аварийный режим)")
        parser.add_argument("--i-know-what-i-am-doing", action="store_true",
                            help="Подтверждение для --force-setup-reset")

    def handle(self, *args, **opts):
        if opts["force_setup_reset"] and not opts["i_know_what_i_am_doing"]:
            raise CommandError(
                "Для сброса setup-фазы добавьте --i-know-what-i-am-doing"
            )

        if os.name != "nt" and os.geteuid() != 0:
            raise CommandError(
                "Команда должна запускаться от root (аварийный путь)."
            )

        username = opts["username"]
        email = opts["email"] or f"{username}@localhost"

        with transaction.atomic():
            if opts["force_setup_reset"]:
                boot = SuperuserBootstrap.get()
                boot.is_setup_complete = False
                boot.setup_completed_at = None
                boot.save()
                self.stdout.write(self.style.WARNING(
                    "Setup-фаза сброшена. Приложение вернётся в мастер настройки."
                ))

            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": email,
                    "is_active": True,
                    "is_staff": False,
                    "is_superuser": False,
                },
            )
            if created:
                self.stdout.write(f"Создан пользователь {username}")
            else:
                self.stdout.write(f"Используем существующего {username}")

            ra, ra_created = RoleAssignment.objects.get_or_create(
                user=user,
                role=Role.SUPERVISOR.value,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=0,
                revoked_at__isnull=True,
                defaults={
                    "granted_by": None,
                },
            )
            if ra_created:
                self.stdout.write(f"Выдана роль SUPERVISOR (GLOBAL) для {username}")
            else:
                self.stdout.write(f"Роль SUPERVISOR уже есть у {username}")

            try:
                AuthAuditLog.objects.create(
                    event=AuthAuditLog.Event.ROLE_GRANTED,
                    target_user=user,
                    detail={"role": Role.SUPERVISOR.value,
                            "source": "bootstrap_supervisor"},
                )
            except Exception:
                pass

        self.stdout.write(self.style.SUCCESS(
            f"Готово. SUPERVISOR'ов: "
            f"{RoleAssignment.objects.filter(role=Role.SUPERVISOR.value, revoked_at__isnull=True).values('user').distinct().count()}"
        ))