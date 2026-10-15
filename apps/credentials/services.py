from __future__ import annotations

from typing import Optional

from loguru import logger

from apps.secrets.services import get_secret

from .models import Credential


class CredentialError(Exception):
    pass


def resolve_credential(
    host, *, kind: str, name: str | None = None,
) -> Credential | None:
    """Найти подходящий Credential для хоста.

    Приоритет scope (специфичный → общий):
        1) host == host
        2) host_set == host.host_set
        3) domain == host.domain (с host_set IS NULL, host IS NULL)
    Если name задан — используется явный выбор (и scope проверяется).
    """
    qs = Credential.objects.filter(kind=kind, is_active=True)

    if name:
        cred = qs.filter(name=name).first()
        if cred is None:
            raise CredentialError(
                f"credential {name!r} не найден или неактивен"
            )
        _ensure_credential_applies(cred, host)
        return cred

    # 1) host
    cred = qs.filter(host=host).first()
    if cred:
        return cred

    # 2) host_set
    cred = qs.filter(host_set=host.host_set, host__isnull=True).first()
    if cred:
        return cred

    # 3) domain
    cred = qs.filter(
        domain=host.domain, host_set__isnull=True, host__isnull=True,
    ).first()
    if cred:
        return cred

    return None


def _ensure_credential_applies(cred: Credential, host) -> None:
    """Проверка, что credential применим к хосту."""
    if cred.host_id and cred.host_id != host.pk:
        raise CredentialError(
            f"credential {cred.name!r} привязан к хосту "
            f"{cred.host.hostname}, а не к {host.hostname}"
        )
    if cred.host_set_id and cred.host_set_id != host.host_set_id:
        raise CredentialError(
            f"credential {cred.name!r} привязан к набору "
            f"{cred.host_set.name}, а не к {host.host_set.name}"
        )
    if cred.domain_id and cred.domain_id != host.domain_id:
        raise CredentialError(
            f"credential {cred.name!r} привязан к домену "
            f"{cred.domain.name}, а не к {host.domain.name}"
        )


def get_credential_value(
    credential: Credential, *, field: str = "password",
) -> str | None:
    """Прочитать значение секрета, связанного с credential.

    field ∈ {"password", "ssh_key", "passphrase"}.
    Возвращает None, если секрет не задан или не читается.
    """
    ref = {
        "password": credential.secret_password,
        "ssh_key": credential.secret_ssh_key,
        "passphrase": credential.secret_passphrase,
    }.get(field)

    if ref is None:
        return None

    try:
        return get_secret(ref.path, "value", audit=False)
    except Exception as exc:
        logger.error(
            f"credentials: не удалось прочитать {ref.path}: {exc}"
        )
        return None


def create_credential(
    *,
    name: str,
    kind: str,
    password: str | None = None,
    ssh_key: str | None = None,
    passphrase: str | None = None,
    domain=None, host_set=None, host=None,
    username: str = "",
    description: str = "",
    user=None,
) -> Credential:
    """Создать credential и связанные SecretRef'ы.

    Все секреты сохраняются через secrets.services.set_secret.
    """
    from apps.secrets.models import SecretRef
    from apps.secrets.services import set_secret

    cred = Credential(
        name=name, kind=kind, username=username,
        description=description,
        domain=domain, host_set=host_set, host=host,
    )
    cred.full_clean()
    cred.save()

    if password is not None:
        set_secret(
            cred.secret_path_password, 
            "value", 
            password,
            display_name=f"Credential: {name} (password)",
            user=user,
            domain=domain, 
            host_set=host_set, 
            host=host,
        )
        ref = SecretRef.objects.filter(
            backend="local", path=cred.secret_path_password, key="value",
        ).first()
        if ref:
            cred.secret_password = ref

    if ssh_key is not None:
        set_secret(
            cred.secret_path_ssh_key, 
            "value", 
            ssh_key,
            display_name=f"Credential: {name} (ssh_key)",
            user=user,
            domain=domain, 
            host_set=host_set, 
            host=host,
        )
        ref = SecretRef.objects.filter(
            backend="local", path=cred.secret_path_ssh_key, key="value",
        ).first()
        if ref:
            cred.secret_ssh_key = ref

    if passphrase is not None:
        set_secret(
            cred.secret_path_passphrase, 
            "value", 
            passphrase,
            display_name=f"Credential: {name} (passphrase)",
            user=user,
            domain=domain, 
            host_set=host_set, 
            host=host,
        )
        ref = SecretRef.objects.filter(
            backend="local", path=cred.secret_path_passphrase, key="value",
        ).first()
        if ref:
            cred.secret_passphrase = ref

    cred.save()
    return cred