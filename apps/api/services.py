from __future__ import annotations

from datetime import UTC, datetime, timezone

from loguru import logger

from apps.deploy.models import Agent, Deployment, ServerIdentity
from apps.deploy.services import encrypt_for_agent, iso_utc, sign_rendered_config


def _resolve_os_family(host) -> str:
    platform = host.host_set.platform
    return "windows" if platform == "windows" else "linux"


def _resolve_distro(host) -> str:
    platform = host.host_set.platform
    if platform.startswith("linux."):
        return platform.split(".", 1)[1]
    return platform


def _collect_secrets(host, agent: Agent) -> dict:
    from apps.credentials.services import (
        CredentialError,
        get_credential_value,
        resolve_credential,
    )

    secrets_box: dict[str, dict] = {}
    settings = host.resolved_settings()

    # --- domain_join ---
    dj = settings.get("domain_join", {}) or {}
    if dj.get("enabled"):
        try:
            cred = resolve_credential(
                host,
                kind="domain_password",
                name=dj.get("credential"),   # явный выбор, если задан
            )
        except CredentialError as exc:
            logger.error(f"domain_join: {exc}")
            cred = None

        if cred is None:
            logger.warning(
                f"domain_join: для {host.hostname} не найден credential "
                f"(kind=domain_password)"
            )
        else:
            password = get_credential_value(cred, field="password")
            if password:
                secrets_box["domain_join_password"] = encrypt_for_agent(
                    agent.pubkey_x25519, password,
                )
                secrets_box["domain_join_username"] = encrypt_for_agent(
                    agent.pubkey_x25519, cred.username or "Administrator",
                )
            else:
                logger.warning(
                    f"domain_join: credential {cred.name!r} без пароля"
                )

    return secrets_box


def build_rendered_config(deployment: Deployment, agent: Agent) -> dict:
    """Собирает RenderedConfig из моделей + подписывает ключом сервера."""
    host = agent.host
    identity = ServerIdentity.get_identity()

    now = datetime.now(UTC)
    config: dict = {
        "schema_version": "1.0",
        "deployment_id": str(deployment.id),
        "generated_at": iso_utc(now),
        "expires_at": None,
        "host": {
            "hostname": host.hostname,
            "fqdn": host.fqdn or None,
            "os_family": _resolve_os_family(host),
            "distro": _resolve_distro(host),
            "distro_version": "",
        },
        "settings": host.resolved_settings(),
        "hardening": {
            "mode": "apply",
            "checks": (host.resolved_hardening() or {}).get("checks", []),
        },
        "secrets": _collect_secrets(host, agent),
    }
    return sign_rendered_config(config, identity.privkey_ed25519)