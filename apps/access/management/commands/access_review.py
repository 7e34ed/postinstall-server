"""Ручной запуск access review и просмотр статуса."""
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.access.models import AccessReviewItem, AccessReviewRun
from apps.access.services import start_access_review


class Command(BaseCommand):
    help = "Access review: запуск и просмотр"

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="cmd")
        sub.add_parser("start", help="Запустить новый review")
        sub.add_parser("list", help="Список прогонов")
        show = sub.add_parser("show", help="Детали прогона")
        show.add_argument("run_id")

    def handle(self, *args, **opts):
        cmd = opts.get("cmd") or "list"
        if cmd == "start":
            run = start_access_review(notes="Запущено вручную")
            self.stdout.write(f"Run: {run.id}, items: {run.total_assignments}")
        elif cmd == "list":
            for run in AccessReviewRun.objects.all()[:20]:
                self.stdout.write(
                    f"{run.id} {run.started_at:%Y-%m-%d} "
                    f"[{run.status}] "
                    f"total={run.total_assignments} "
                    f"confirmed={run.confirmed} "
                    f"revoked={run.revoked} "
                    f"pending={run.pending}"
                )
        elif cmd == "show":
            run = AccessReviewRun.objects.get(pk=opts["run_id"])
            self.stdout.write(f"Run: {run.id} [{run.status}]")
            for item in run.items.select_related("assignment", "assignment__user"):
                self.stdout.write(
                    f"  {item.assignment.user.username} "
                    f"role={item.assignment.role} "
                    f"scope={item.assignment.scope_type}:{item.assignment.scope_id} "
                    f"status={item.status}"
                )