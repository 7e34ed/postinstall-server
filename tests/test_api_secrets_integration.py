import pytest


@pytest.mark.django_db
def test_collect_secrets_uses_credential(domain, host_set, host, runtime_unsealed):
    from apps.api.services import _collect_secrets
    from apps.credentials.services import create_credential
    from apps.deploy.models import Agent

    create_credential(
        name="d-admin", kind="domain_password",
        password="s3cret", username="Administrator",
        domain=domain,
    )
    host.overrides = {
        "domain_join": {"enabled": True, "domain": "test.local"},
    }
    host.save()

    # нужен agent для шифрования
    _, xpub = __import__("apps.deploy.services", fromlist=["x"]).generate_x25519_keypair()
    agent = Agent.objects.create(
        host=host, pubkey_ed25519="k1", pubkey_x25519=xpub.decode(),
    )

    box = _collect_secrets(host, agent)
    assert "domain_join_password" in box
    assert "domain_join_username" in box