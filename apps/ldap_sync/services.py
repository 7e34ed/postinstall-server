"""Высокоуровневые операции ldap_sync.

Принципы:
  * никогда не создаём User автоматически;
  * никогда не используем LDAP как auth backend;
  * только чтение.
"""
from __future__ import annotations

from datetime import datetime

from django.utils import timezone
from loguru import logger

from apps.access.models import AuthAuditLog, log_auth_event

from .client import LDAPClient, LDAPSettings, is_user_active
from .models import LDAPHostMap, LDAPSyncRun


def settings_for_domain(domain) -> LDAPSettings | None:
    """Собрать LDAPSettings из Domain.

    Пароль берётся из связанного SecretRef (если есть).
    """
    if not domain.ldap_url or not domain.ldap_base_dn:
        return None

    password = ""
    if domain.ldap_bind_secret_ref_id:
        from apps.secrets.services import get_secret
        ref = domain.ldap_bind_secret_ref
        password = get_secret(ref.path, "value", audit=False) or ""

    return LDAPSettings(
        url=domain.ldap_url,
        base_dn=domain.ldap_base_dn,
        bind_dn=domain.ldap_bind_dn or "",
        bind_password=password,
    )


# ============================================================
#  Верификация при enrollment
# ============================================================

def verify_user_active(email: str, *, domain=None) -> tuple[bool, str]:
    """Проверить, что email соответствует активной учётке в AD.

    Возвращает (ok, reason). Если домен без LDAP-настроек — (True, "no ldap").
    """
    if not domain:
        return True, "no domain"
    settings = settings_for_domain(domain)
    if settings is None:
        return True, "domain without ldap"

    try:
        with LDAPClient(settings) as c:
            attrs = c.find_user_by_email(email)
    except Exception as exc:
        logger.warning(f"ldap_sync: verify_user_active failed: {exc}")
        # fail-open при недоступности LDAP — enrollment не должен ломаться
        return True, f"ldap unavailable: {exc}"

    if attrs is None:
        return False, f"user {email!r} not found in AD"

    if not is_user_active(attrs):
        return False, f"user {email!r} is disabled/locked in AD"

    return True, "ok"


# ============================================================
#  Lookup и аугментация
# ============================================================

def lookup_user(email: str, *, domain=None) -> dict | None:
    if not domain:
        return None
    settings = settings_for_domain(domain)
    if settings is None:
        return None
    try:
        with LDAPClient(settings) as c:
            return c.find_user_by_email(email)
    except Exception as exc:
        logger.warning(f"ldap_sync: lookup_user failed: {exc}")
        return None


def augment_user(user, *, domain=None, run: LDAPSyncRun | None = None) -> bool:
    """Заполнить first_name / last_name / email из AD.

    Не перезаписывает непустые поля, если явно не указано.
    Возвращает True, если что-то изменилось.
    """
    from django.contrib.auth import get_user_model

    if not user.email:
        return False

    attrs = lookup_user(user.email, domain=domain)
    if attrs is None:
        if run:
            run.skipped += 1
        return False

    changed = False
    given = _first(attrs.get("givenName"))
    sn = _first(attrs.get("sn"))
    display = _first(attrs.get("displayName"))

    if given and not user.first_name:
        user.first_name = given
        changed = True
    if sn and not user.last_name:
        user.last_name = sn
        changed = True

    if not user.first_name and not user.last_name and display:
        # Разделить displayName пополам
        parts = display.split(None, 1)
        user.first_name = parts[0]
        user.last_name = parts[1] if len(parts) > 1 else ""
        changed = True

    if changed:
        user.save(update_fields=["first_name", "last_name"])
        if run:
            run.updated += 1

    return changed


def _first(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return str(v)


# ============================================================
#  Синхронизация хостов
# ============================================================

def sync_hosts_for_domain(domain, *, run: LDAPSyncRun | None = None,
                           ou: str | None = None) -> LDAPSyncRun:
    """Синхронизировать AD-компьютеры в Host.

    Создаёт новые Host (managed=False), обновляет существующие
    по hostname. Помечает исчезнувшие через LDAPHostMap.is_active_in_ad=False.
    """
    from apps.inventory.models import Host, HostSet

    if run is None:
        run = LDAPSyncRun.objects.create(domain=domain, kind=LDAPSyncRun.Kind.HOSTS)

    settings = settings_for_domain(domain)
    if settings is None:
        run.status = LDAPSyncRun.Status.FAILED
        run.error = "LDAP не настроен для домена"
        run.finished_at = timezone.now()
        run.save()
        return run

    try:
        default_set = HostSet.objects.filter(domain=domain).first()
        if default_set is None:
            raise RuntimeError(
                f"нет HostSet для домена {domain.name}; "
                f"создайте хотя бы один перед синком"
            )

        seen_dns: set[str] = set()

        with LDAPClient(settings) as c:
            for attrs in c.list_computers(ou=ou):
                run.found += 1
                try:
                    _process_computer(domain, default_set, attrs, seen_dns, run)
                except Exception as exc:
                    logger.exception(
                        f"ldap_sync: computer {attrs.get('dn')} failed"
                    )
                    run.failed += 1
                    run.details.setdefault("errors", []).append({
                        "dn": attrs.get("dn"),
                        "error": str(exc)[:200],
                    })

        # Помечаем исчезнувшие
        from django.utils import timezone as _tz
        
        for m in LDAPHostMap.objects.filter(domain=domain, is_active_in_ad=True):
            if m.ad_dn not in seen_dns:
                m.is_active_in_ad = False
                m.save(update_fields=["is_active_in_ad"])

        run.status = (
            LDAPSyncRun.Status.SUCCESS if run.failed == 0
            else LDAPSyncRun.Status.FAILED
        )
    except Exception as exc:
        logger.exception("ldap_sync: sync_hosts failed")
        run.status = LDAPSyncRun.Status.FAILED
        run.error = str(exc)[:1000]

    run.finished_at = timezone.now()
    run.save()

    log_auth_event(
        AuthAuditLog.Event.ROLE_GRANTED,   # используем существующий event
        detail={
            "action": "ldap_sync_hosts",
            "domain": domain.name,
            "run_id": str(run.id),
            "found": run.found,
            "created": run.created,
            "updated": run.updated,
        },
    )
    logger.info(
        f"ldap_sync: {domain.name} found={run.found} "
        f"created={run.created} updated={run.updated} failed={run.failed}"
    )
    return run


def _process_computer(domain, default_set, attrs: dict,
                       seen_dns: set[str], run: LDAPSyncRun) -> None:
    from apps.inventory.models import Host

    dn = attrs.get("dn", "")
    sam = _first(attrs.get("sAMAccountName")).rstrip("$")
    dns_name = _first(attrs.get("dNSHostName"))
    if not sam:
        run.skipped += 1
        return

    seen_dns.add(dn)

    hostname = sam.lower()
    existing_map = LDAPHostMap.objects.filter(ad_dn=dn).first()

    if existing_map:
        # Обновляем
        host = existing_map.host
        changed = False
        if dns_name and host.fqdn != dns_name.lower():
            host.fqdn = dns_name.lower()
            changed = True
        if not host.os_family and attrs.get("operatingSystem"):
            host.os_family = _first(attrs["operatingSystem"])[:32]
            changed = True
        if changed:
            host.save()
            run.updated += 1
        existing_map.ad_sam = sam
        existing_map.ad_dns = dns_name
        existing_map.last_seen_in_ad = timezone.now()
        existing_map.is_active_in_ad = True
        existing_map.save()
        return

    # Ищем Host по hostname
    host = Host.objects.filter(domain=domain, hostname=hostname).first()
    created = False
    if host is None:
        host = Host.objects.create(
            domain=domain,
            host_set=default_set,
            hostname=hostname,
            fqdn=dns_name.lower() if dns_name else "",
            os_family=_first(attrs.get("operatingSystem"))[:32],
            managed=False,     # по умолчанию не управляемый
            source=Host.Source.LDAP,
        )
        run.created += 1
        created = True
    else:
        run.skipped += 1

    LDAPHostMap.objects.create(
        domain=domain,
        ad_dn=dn,
        ad_sam=sam,
        ad_dns=dns_name,
        host=host,
        last_seen_in_ad=timezone.now(),
        is_active_in_ad=True,
    )