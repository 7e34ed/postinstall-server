import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from apps.credentials.models import Credential
from apps.credentials.services import (
    CredentialError,
    create_credential,
    get_credential_value,
    resolve_credential,
)
from apps.inventory.models import Domain, Host, HostSet

User = get_user_model()


@pytest.fixture
def domain(db):
    return Domain.objects.create(name="test.local")


@pytest.fixture
def host_set(domain):
    return HostSet.objects.create(
        domain=domain, name="web", platform="linux.debian",
    )


@pytest.fixture
def host(host_set):
    return Host.objects.create(
        domain=host_set.domain, host_set=host_set, hostname="web1",
    )


@pytest.fixture
def runtime_unsealed(db):
    import base64

    from apps.secrets import blob as b
    from apps.secrets.models import ServerKey
    from apps.secrets.runtime import runtime
    salt = b.new_salt()
    kek = b.derive_kek("m", salt)
    blob = b.encrypt_blob(b.empty_blob(), kek)
    ServerKey.objects.create(
        salt=base64.b64encode(salt).decode(),
        blob=base64.b64encode(blob).decode(),
    )
    runtime.seal()
    runtime.unlock("m")
    yield
    runtime.seal()


@pytest.mark.django_db
def test_credential_requires_scope(runtime_unsealed):
    c = Credential(name="x", kind="domain_password")
    with pytest.raises(ValidationError, match="domain"):
        c.full_clean()


@pytest.mark.django_db
def test_create_domain_credential(domain, runtime_unsealed):
    cred = create_credential(
        name="test.local-admin", kind="domain_password",
        password="s3cret", username="Administrator",
        domain=domain,
    )
    assert cred.pk
    assert cred.secret_password is not None
    assert get_credential_value(cred, "password") == "s3cret"


@pytest.mark.django_db
def test_resolve_prefers_host(domain, host_set, host, runtime_unsealed):
    create_credential(name="d", kind="domain_password",
                      password="pwd-domain", domain=domain)
    create_credential(name="s", kind="domain_password",
                      password="pwd-set", host_set=host_set)
    create_credential(name="h", kind="domain_password",
                      password="pwd-host", host=host)

    c = resolve_credential(host, kind="domain_password")
    assert c.name == "h"


@pytest.mark.django_db
def test_resolve_fallback_to_hostset(domain, host_set, host, runtime_unsealed):
    create_credential(name="d", kind="domain_password",
                      password="pwd", domain=domain)
    create_credential(name="s", kind="domain_password",
                      password="pwd2", host_set=host_set)

    c = resolve_credential(host, kind="domain_password")
    assert c.name == "s"


@pytest.mark.django_db
def test_resolve_fallback_to_domain(domain, host_set, host, runtime_unsealed):
    create_credential(name="d", kind="domain_password",
                      password="pwd", domain=domain)

    c = resolve_credential(host, kind="domain_password")
    assert c.name == "d"


@pytest.mark.django_db
def test_resolve_by_name(domain, host_set, host, runtime_unsealed):
    create_credential(name="d", kind="domain_password",
                      password="pwd", domain=domain)
    create_credential(name="other", kind="domain_password",
                      password="pwd2", host_set=host_set)

    c = resolve_credential(host, kind="domain_password", name="d")
    assert c.name == "d"


@pytest.mark.django_db
def test_resolve_by_name_wrong_scope(domain, host_set, host, runtime_unsealed):
    other_domain = Domain.objects.create(name="other.local")
    create_credential(name="x", kind="domain_password",
                      password="pwd", domain=other_domain)

    with pytest.raises(CredentialError, match="домену"):
        resolve_credential(host, kind="domain_password", name="x")


@pytest.mark.django_db
def test_resolve_none_when_no_credentials(host, runtime_unsealed):
    assert resolve_credential(host, kind="domain_password") is None


@pytest.mark.django_db
def test_ssh_key_credential(domain, runtime_unsealed):
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
    cred = create_credential(
        name="key1", kind="ssh_key",
        ssh_key=key,
        domain=domain,
    )
    assert get_credential_value(cred, "ssh_key") == key