from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.authentication import AgentSignatureAuthentication
from apps.api.permissions import IsAgent
from apps.api.serializers import AgentRegisterSerializer
from apps.api.services import build_rendered_config
from apps.deploy.models import (
    Agent,
    Deployment,
    DeploymentReport,
    ServerIdentity,
)

LONG_POLL_TIMEOUT = 30
LONG_POLL_STEP = 1.0


@api_view(["POST"])
@authentication_classes([])          # регистрация без подписи
@permission_classes([AllowAny])
def register(request):
    ser = AgentRegisterSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    data = ser.validated_data

    # 1) Найти Host
    from apps.inventory.models import Host
    host = None
    try:
        host = Host.objects.get(hostname=data["hostname"])
    except Host.DoesNotExist:
        if data.get("fqdn"):
            try:
                host = Host.objects.get(fqdn=data["fqdn"])
            except Host.DoesNotExist:
                pass
    if host is None:
        return Response(
            {"detail": f"host {data['hostname']!r} не найден. "
                       "Добавьте хост через UI или LDAP-синк."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # 2) Валидация публичных ключей
    try:
        serialization.load_pem_public_key(data["pubkey_ed25519"].encode())
        serialization.load_pem_public_key(data["pubkey_x25519"].encode())
    except Exception as exc:
        return Response(
            {"detail": f"invalid pubkey: {exc}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # 3) Создать/обновить агента
    agent, created = Agent.objects.update_or_create(
        host=host,
        defaults={
            "pubkey_ed25519": data["pubkey_ed25519"],
            "pubkey_x25519": data["pubkey_x25519"],
            "version": data["agent_version"],
            "is_active": True,
            "last_seen_ip": _client_ip(request),
        },
    )

    host.agent_registered_at = timezone.now()
    host.agent_version = data["agent_version"]
    host.save(update_fields=["agent_registered_at", "agent_version"])

    identity = ServerIdentity.get_identity()

    return Response(
        {
            "agent_id": str(agent.agent_id),
            "server_pubkey_ed25519": identity.pubkey_ed25519,
        },
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )


@api_view(["POST"])
@authentication_classes([AgentSignatureAuthentication])
@permission_classes([IsAgent])
def heartbeat(request):
    agent: Agent = request.auth
    now = timezone.now()

    agent.last_seen_at = now
    agent.last_seen_ip = _client_ip(request)
    agent.version = request.data.get("agent_version", agent.version or "")
    agent.save(update_fields=["last_seen_at", "last_seen_ip", "version"])

    agent.host.agent_last_seen_at = now
    agent.host.agent_version = agent.version
    agent.host.save(update_fields=["agent_last_seen_at", "agent_version"])

    return Response({"status": "ok", "ts": now.isoformat()})


@api_view(["GET"])
@authentication_classes([AgentSignatureAuthentication])
@permission_classes([IsAgent])
def tasks(request):
    """Long-poll за задачей.

    Упрощение: poll каждые LONG_POLL_STEP секунд, максимум LONG_POLL_TIMEOUT.
    Для прода — Redis pub/sub, чтобы не занимать воркер.
    """
    agent: Agent = request.auth
    deadline = time.monotonic() + LONG_POLL_TIMEOUT

    while time.monotonic() < deadline:
        deployment = (
            Deployment.objects
            .filter(host=agent.host, status=Deployment.Status.PENDING)
            .order_by("-priority", "created_at")
            .first()
        )
        if deployment:
            deployment.status = Deployment.Status.DISPATCHED
            deployment.dispatched_at = timezone.now()
            rendered = build_rendered_config(deployment, agent)
            deployment.rendered_config = rendered
            deployment.save(update_fields=["status", "dispatched_at", "rendered_config"])
            return Response(rendered)
        time.sleep(LONG_POLL_STEP)

    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["POST"])
@authentication_classes([AgentSignatureAuthentication])
@permission_classes([IsAgent])
def report(request):
    agent: Agent = request.auth
    deployment_id = request.data.get("deployment_id")
    if not deployment_id:
        return Response({"detail": "deployment_id missing"},
                        status=status.HTTP_400_BAD_REQUEST)

    try:
        deployment = Deployment.objects.get(id=deployment_id, host=agent.host)
    except (Deployment.DoesNotExist, ValueError):
        return Response({"detail": "deployment not found"},
                        status=status.HTTP_404_NOT_FOUND)

    report_status = request.data.get("status", "failed")
    deployment.status = _map_status(report_status)
    deployment.finished_at = timezone.now()
    deployment.save(update_fields=["status", "finished_at"])

    DeploymentReport.objects.update_or_create(
        deployment=deployment,
        defaults={
            "status": report_status,
            "started_at": request.data.get("started_at") or timezone.now(),
            "finished_at": request.data.get("finished_at") or timezone.now(),
            "modules": request.data.get("modules", []),
            "hardening": request.data.get("hardening", []),
            "agent_version": request.data.get("agent_version", ""),
            "error": request.data.get("error", ""),
            "raw": request.data,
        },
    )

    return Response({"status": "ok"})


def _map_status(report_status: str) -> str:
    return {
        "success": Deployment.Status.SUCCESS,
        "partial": Deployment.Status.PARTIAL,
        "failed": Deployment.Status.FAILED,
    }.get(report_status, Deployment.Status.FAILED)


def _client_ip(request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")