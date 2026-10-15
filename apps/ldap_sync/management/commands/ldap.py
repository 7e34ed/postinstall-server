"""Управление LDAP-синком.

    manage.py ldap test <domain_name> <email>
    manage.py ldap sync-hosts <domain_name>
    manage.py ldap lookup <domain_name> <email>
"""
from django.core.management.base import BaseCommand, CommandError

from apps.inventory.models import Domain
from apps.ldap_sync.models import LDAPSyncRun
from apps.ldap_sync.services import (
    lookup_user,
    sync_hosts_for_domain,
    verify_user_active,
)


class Command(BaseCommand):
    help = "LDAP-синхронизация и проверка"

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="cmd", required=True)

        t = sub.add_parser("test", help="Проверить пользователя")
        t.add_argument("domain")
        t.add_argument("email")

        s = sub.add_parser("sync-hosts", help="Синхронизировать компьютеры")
        s.add_argument("domain")

        l = sub.add_parser("lookup", help="Показать атрибуты")
        l.add_argument("domain")
        l.add_argument("email")

    def handle(self, *args, **opts):
        try:
            domain = Domain.objects.get(name=opts["domain"])
        except Domain.DoesNotExist:
            raise CommandError(f"домен {opts['domain']!r} не найден")  # noqa: B904

        if opts["cmd"] == "test":
            ok, why = verify_user_active(opts["email"], domain=domain)
            self.stdout.write(f"{ok}: {why}")
        elif opts["cmd"] == "lookup":
            attrs = lookup_user(opts["email"], domain=domain)
            if not attrs:
                self.stdout.write("не найдено")
            else:
                for k, v in sorted(attrs.items()):
                    self.stdout.write(f"  {k} = {v}")
        elif opts["cmd"] == "sync-hosts":
            run = LDAPSyncRun.objects.create(
                domain=domain, kind=LDAPSyncRun.Kind.HOSTS,
            )
            r = sync_hosts_for_domain(domain, run=run)
            self.stdout.write(
                f"run={r.id} status={r.status} "
                f"found={r.found} created={r.created} "
                f"updated={r.updated} failed={r.failed}"
            )