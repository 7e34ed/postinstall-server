"""Сборка финального settings и hardening для хоста.

Порядок слоёв (снизу вверх):
    1. Профили HostSet (по order)
    2. Профили Host.extra_profiles (по order)
    3. HostSet.common_config
    4. Host.overrides
Каждый следующий перекрывает предыдущий для скалярных значений,
списки — конкатенируются там, где это осмысленно (порты, jails).
"""
from __future__ import annotations

import copy
from typing import Any

from apps.core.utils import deep_merge

from .models import ConfigProfile

# def _deep_merge(dst: dict, src: dict) -> dict:
#     for k, v in (src or {}).items():
#         if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
#             _deep_merge(dst[k], v)
#         else:
#             dst[k] = copy.deepcopy(v)
#     return dst


def _collect_profiles(host) -> list[ConfigProfile]:
    profiles: list[ConfigProfile] = []
    for link in host.host_set.profile_links.select_related("profile").order_by("order", "id"):
        profiles.append(link.profile)
    for link in host.extra_profile_links.select_related("profile").order_by("order", "id"):
        profiles.append(link.profile)
    return [p for p in profiles if p.is_active]


def resolve_for_host(host) -> dict:
    """Возвращает финальный `settings` (то, что уйдёт агенту)."""
    profiles = _collect_profiles(host)

    # 1. Базовая сборка: common_config + overrides
    # settings = copy.deepcopy(host.host_set.common_config or {})
    settings = deep_merge(host.host_set.common_config or {}, host.overrides or {})

    # 2. Агрегация из профилей
    extra_ports: list[int] = []
    jails: list[str] = []
    apt_packages: list[str] = []
    repositories: list[dict] = []
    certificates: list[dict] = []
    package_installs: list[dict] = []
    scripts: list[str] = []

    for p in profiles:
        extra_ports.extend(p.extra_ports or [])
        jails.extend(p.jails or [])
        apt_packages.extend(p.packages or [])
        for r in p.repositories.all():
            repositories.append({
                "name": r.name,
                "url": r.url,
                "components": r.components,
                "key_url": r.key_url or None,
                "key_content": r.key_content or None,
            })
        for c in p.certificates.all():
            certificates.append({"name": c.name, "content": c.content_b64})
        for pkg in p.package_installs.all():
            package_installs.append({
                "name": pkg.name, "url": pkg.url,
                "sha256": pkg.sha256 or None,
            })
        if p.postinstall_script:
            scripts.append(p.postinstall_script)
        # settings_override — поверх
        # _deep_merge(settings, p.settings or {})
        settings = deep_merge(settings or {}, p.settings or {})

    # 3. Слияние агрегатов в settings

    # allowed_ports
    ports = set(settings.get("general", {}).get("allowed_ports", []))
    ports.update(int(x) for x in extra_ports if str(x).lstrip("-").isdigit())
    settings.setdefault("general", {})["allowed_ports"] = sorted(ports)

    # fail2ban.jails
    fj = set(settings.get("fail2ban", {}).get("jails", []))
    fj.update(jails)
    settings.setdefault("fail2ban", {})["jails"] = sorted(fj)

    # apt-пакеты — имена, отдельное поле (агент ставит через apt)
    if apt_packages:
        settings.setdefault("packages", {})["apt"] = sorted(set(apt_packages))

    # repositories
    if repositories:
        settings.setdefault("repositories", {})["items"] = repositories

    # certificates
    if certificates:
        settings.setdefault("certificates", {})["items"] = certificates

    # package_installs — по URL
    if package_installs:
        existing = list(settings.get("dependencies", {}).get("packages", []))
        existing.extend(package_installs)
        settings.setdefault("dependencies", {})["packages"] = existing

    # postinstall_script
    if scripts:
        settings["postinstall_script"] = "\n\n".join(scripts)

    # hostname всегда прокидываем
    settings.setdefault("host", {})["hostname"] = host.hostname

    return settings


def resolve_hardening_for_host(host) -> dict:
    """Аналогично для hardening."""
    profiles = _collect_profiles(host)

    # базовая база )
    base_checks = (host.host_set.common_hardening or {}).get("checks", [])
    base_mode = (host.host_set.common_hardening or {}).get("mode", "apply")

    # профили
    profile_checks: list[dict] = []
    profile_mode = None
    for p in profiles:
        h = p.hardening or {}
        if h.get("mode"):
            profile_mode = h["mode"]
        profile_checks.extend(h.get("checks", []))

    # overrides хоста
    override = host.hardening_overrides or {}
    override_checks = override.get("checks", [])

    # Дедупликация по id: побеждает последний
    merged: dict[str, dict] = {}
    for c in base_checks + profile_checks + override_checks:
        if isinstance(c, dict) and c.get("id"):
            merged[c["id"]] = c

    return {
        "mode": override.get("mode") or profile_mode or base_mode,
        "checks": list(merged.values()),
    }