from __future__ import annotations

import base64
import time
import uuid

from cryptography.hazmat.primitives import serialization
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from apps.deploy.models import Agent
from apps.deploy.services import canonical_payload

AUTH_SCHEME = "PSI-Agent"
TIMESTAMP_WINDOW = 300  # ±5 минут


class AgentSignatureAuthentication(BaseAuthentication):
    """Аутентификация агента по Ed25519-подписи запроса.

    Формат заголовка Authorization:
        PSI-Agent <unix_ts>:<base64_signature>

    Подписывается канонический payload:
        <METHOD>\\n
        <PATH>\\n
        <UNIX_TS>\\n
        <SHA256(body) в hex>
    """

    def authenticate(self, request):
        header = request.headers.get("Authorization", "")
        if not header.startswith(AUTH_SCHEME + " "):
            return None

        agent_id_str = request.headers.get("X-PSI-Agent-Id", "").strip()
        if not agent_id_str:
            raise AuthenticationFailed("X-PSI-Agent-Id missing")

        try:
            agent_uuid = uuid.UUID(agent_id_str)
        except ValueError as exc:
            raise AuthenticationFailed("invalid agent_id format") from exc

        try:
            agent = Agent.objects.select_related("host", "host__domain").get(
                agent_id=agent_uuid, is_active=True,
            )
        except Agent.DoesNotExist as exc:
            raise AuthenticationFailed("unknown or inactive agent") from exc

        payload = header[len(AUTH_SCHEME) + 1:]
        try:
            ts_str, sig_b64 = payload.split(":", 1)
            ts = int(ts_str)
            sig = base64.b64decode(sig_b64)
        except Exception as exc:
            raise AuthenticationFailed("bad Authorization format") from exc

        now = int(time.time())
        if abs(now - ts) > TIMESTAMP_WINDOW:
            raise AuthenticationFailed("timestamp out of allowed window")

        # Канонический payload для проверки
        body = request.body or b""
        import hashlib
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = (
            f"{request.method.upper()}\n{request.path}\n{ts}\n{body_hash}"
        ).encode()

        try:
            pub = serialization.load_pem_public_key(agent.pubkey_ed25519.encode())
            pub.verify(sig, canonical)
        except Exception as exc:
            raise AuthenticationFailed(f"invalid signature: {exc}") from exc

        # request.user = None; request.auth = agent
        return (None, agent)

    def authenticate_header(self, request):
        return AUTH_SCHEME