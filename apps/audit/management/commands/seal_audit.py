"""Запечатать новые записи аудита.

    manage.py seal_audit [--source SOURCE]
"""
from django.core.management.base import BaseCommand

from apps.audit.models import AuditSeal
from apps.audit.sealing import seal_source


class Command(BaseCommand):
    help = "Запечатать новые записи аудита"

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=[s for s in AuditSeal.Source.values])

    def handle(self, *args, **opts):
        sources = [opts["source"]] if opts["source"] else list(AuditSeal.Source.values)
        for src in sources:
            r = seal_source(src)
            if r is None:
                self.stdout.write(f"{src}: нет новых записей")
            else:
                self.stdout.write(
                    f"{src}: sealed [{r.first_id}..{r.last_id}] ({r.count})"
                )