"""Выгрузить новые записи аудита.

    manage.py export_audit [--syslog] [--file PATH]
"""
from pathlib import Path

from django.core.management.base import BaseCommand

from apps.audit.export import export_to_file, export_to_syslog


class Command(BaseCommand):
    help = "Экспорт аудита (syslog/file)"

    def add_arguments(self, parser):
        parser.add_argument("--syslog", action="store_true")
        parser.add_argument("--file", type=Path, default=None)

    def handle(self, *args, **opts):
        do_syslog = opts["syslog"] or (not opts["file"])
        if do_syslog:
            r = export_to_syslog()
            self.stdout.write(f"syslog: {r}")
        if opts["file"]:
            r = export_to_file(path=opts["file"])
            self.stdout.write(f"file: {r}")