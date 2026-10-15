"""Проверка целостности аудита.

    manage.py verify_audit [--source SOURCE] [--max-records N] [--from ID]
"""
from django.core.management.base import BaseCommand

from apps.audit.models import AuditSeal
from apps.audit.sealing import verify_source


class Command(BaseCommand):
    help = "Проверка целостности цепочки аудита"

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=[s for s in AuditSeal.Source.values])
        parser.add_argument("--max-records", type=int, default=None)
        parser.add_argument("--from-id", type=int, default=0)

    def handle(self, *args, **opts):
        sources = [opts["source"]] if opts["source"] else list(AuditSeal.Source.values)
        bad = 0
        for src in sources:
            r = verify_source(src, from_id=opts["from_id"],
                               max_records=opts["max_records"])
            mark = self.style.SUCCESS("OK") if r.status == "ok" \
                else self.style.ERROR(r.status.upper())
            self.stdout.write(
                f"{src}: {mark} "
                f"(records={r.checked_records}, seals={r.checked_seals}, "
                f"broken_at={r.first_broken_id})"
            )
            if r.status != "ok":
                bad += 1
                if r.details.get("records", {}).get("breaks"):
                    for b in r.details["records"]["breaks"][:5]:
                        self.stdout.write(
                            f"  record {b['id']}: "
                            f"expected_hash={b['expected_hash'][:16]}… "
                            f"actual={b['actual_hash'][:16]}…"
                        )
                if r.details.get("seals", {}).get("bad_seals"):
                    for b in r.details["seals"]["bad_seals"][:5]:
                        self.stdout.write(f"  seal {b['id']}: {b['reason']}")
        if bad:
            raise SystemExit(1)