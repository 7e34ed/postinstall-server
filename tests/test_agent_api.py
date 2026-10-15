import base64
import json
import time
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from django.urls import reverse

from apps.deploy.models import Agent, Deployment, ServerIdentity
from apps.deploy.services import generate_ed25519_keypair
from apps.inventory.models import Domain, Host, HostSet


@pytest.fixture
def host(db):
    d = Domain.objects.create(name="test.local", domain_join_password="s3cret")
    s = HostSet.objects.create(domain=d, name="default", platform="linux.debian")
    return Host.objects.create(domain=d, host_set=s, hostname="web1")


@pytest.fixture
def agent_keys():
    priv, pub = generate_ed25519_keypair()
    return priv, pub


def _sign(priv_pem: bytes, method: str, path: str, body: bytes,
          agent_id: str) -> dict:
    import hashlib

    ts = int(time.time())
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{ts}\n{body_hash}".encode()
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(canonical)
    return {
        "Authorization": f"PSI-Agent {ts}:{base64.b64encode(sig).decode()}",
        "X-PSI-Agent-Id": agent_id,
        "Content-Type": "application/json",
    }


@pytest.mark.django_db
def test_register_unknown_host(client):
    r = client.post(
        "/api/v1/agent/register",
        data=json.dumps({
            "hostname": "unknown",
            "os": "linux", "distro": "debian", "distro_version": "12",
            "arch": "amd64", "agent_version": "0.1.0",
            "pubkey_ed25519": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            "pubkey_x25519": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        }),
        content_type="application/json",
    )
    assert r.status_code == 404


@pytest.mark.django_db
def test_register_and_heartbeat(client, host, agent_keys):
    priv, pub = agent_keys
    # сгенерируем X25519
    from apps.deploy.services import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()

    r = client.post(
        "/api/v1/agent/register",
        data=json.dumps({
            "hostname": "web1",
            "os": "linux", "distro": "debian", "distro_version": "12",
            "arch": "amd64", "agent_version": "0.1.0",
            "pubkey_ed25519": pub.decode(),
            "pubkey_x25519": xpub.decode(),
        }),
        content_type="application/json",
    )
    assert r.status_code == 201
    data = r.json()
    agent_id = data["agent_id"]
    assert "server_pubkey_ed25519" in data

    # heartbeat
    body = json.dumps({"agent_version": "0.1.0"}).encode()
    headers = _sign(priv, "POST", "/api/v1/agent/heartbeat", body, agent_id)
    r = client.post("/api/v1/agent/heartbeat", data=body, **headers)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.django_db
def test_heartbeat_bad_signature(client, host, agent_keys):
    priv, pub = agent_keys
    from apps.deploy.services import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()

    r = client.post(
        "/api/v1/agent/register",
        data=json.dumps({
            "hostname": "web1",
            "os": "linux", "distro": "debian", "distro_version": "12",
            "arch": "amd64", "agent_version": "0.1.0",
            "pubkey_ed25519": pub.decode(),
            "pubkey_x25519": xpub.decode(),
        }),
        content_type="application/json",
    )
    agent_id = r.json()["agent_id"]

    body = b'{"agent_version":"0.1.0"}'
    ts = int(time.time())
    headers = {
        "Authorization": f"PSI-Agent {ts}:{base64.b64encode(b'x'*64).decode()}",
        "X-PSI-Agent-Id": agent_id,
        "Content-Type": "application/json",
    }
    r = client.post("/api/v1/agent/heartbeat", data=body, **headers)
    assert r.status_code == 403   # AuthenticationFailed → 403


@pytest.mark.django_db
def test_tasks_empty(client, host, agent_keys):
    priv, pub = agent_keys
    from apps.deploy.services import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()

    r = client.post(
        "/api/v1/agent/register",
        data=json.dumps({
            "hostname": "web1",
            "os": "linux", "distro": "debian", "distro_version": "12",
            "arch": "amd64", "agent_version": "0.1.0",
            "pubkey_ed25519": pub.decode(),
            "pubkey_x25519": xpub.decode(),
        }),
        content_type="application/json",
    )
    agent_id = r.json()["agent_id"]

    # long-poll в тесте не должен висеть 30 секунд — уменьшим через monkeypatch
    import apps.api.views.agent as v
    old_timeout = v.LONG_POLL_TIMEOUT
    old_step = v.LONG_POLL_STEP
    v.LONG_POLL_TIMEOUT = 0.1
    v.LONG_POLL_STEP = 0.05
    try:
        body = b""
        headers = _sign(priv, "GET", "/api/v1/agent/tasks", body, agent_id)
        r = client.get("/api/v1/agent/tasks", **headers)
        assert r.status_code == 204
    finally:
        v.LONG_POLL_TIMEOUT = old_timeout
        v.LONG_POLL_STEP = old_step


@pytest.mark.django_db
def test_tasks_returns_deployment(client, host, agent_keys):
    priv, pub = agent_keys
    from apps.deploy.services import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()

    r = client.post(
        "/api/v1/agent/register",
        data=json.dumps({
            "hostname": "web1",
            "os": "linux", "distro": "debian", "distro_version": "12",
            "arch": "amd64", "agent_version": "0.1.0",
            "pubkey_ed25519": pub.decode(),
            "pubkey_x25519": xpub.decode(),
        }),
        content_type="application/json",
    )
    agent_id = r.json()["agent_id"]

    deployment = Deployment.objects.create(host=host)

    body = b""
    headers = _sign(priv, "GET", "/api/v1/agent/tasks", body, agent_id)
    r = client.get("/api/v1/agent/tasks", **headers)
    assert r.status_code == 200
    data = r.json()
    assert data["deployment_id"] == str(deployment.id)
    assert "signature" in data
    assert data["signature"]["algo"] == "ed25519"

    deployment.refresh_from_db()
    assert deployment.status == Deployment.Status.DISPATCHED