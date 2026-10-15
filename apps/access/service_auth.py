"""Аутентификация по сервисным токенам.

Формат: Authorization: Bearer sa_<account>_<random>
Хранится только sha256-хеш.

DRF-класс ServiceAccountTokenAuthentication и Django-хелпер
for API-эндпоинтов.
"""
from __future__ import annotations

from django.http import HttpRequest
from loguru import logger

from .models import ServiceAccount, ServiceAccountToken


class ServiceAccountAuthError(Exception):
    pass


def _extract_bearer(request: HttpRequest) -> str:
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header:
        return ""
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def authenticate_request(request: HttpRequest) -> ServiceAccount | None:
    """Вернуть ServiceAccount или None.

    Не бросает исключений. Не трогает request.user.
    """
    plaintext = _extract_bearer(request)
    if not plaintext:
        return None

    token = ServiceAccountToken.verify(plaintext)
    if token is None:
        logger.info(
            "service_auth: invalid token from %s",
            request.META.get("REMOTE_ADDR", "?"),
        )
        return None

    try:
        token.touch()
    except Exception:
        logger.exception("service_auth: touch failed")

    return token.account


# --- DRF ---

try:
    from rest_framework.authentication import BaseAuthentication
    from rest_framework.exceptions import AuthenticationFailed

    class ServiceAccountTokenAuthentication(BaseAuthentication):
        """DRF: аутентификация сервисного аккаунта.

        Если токен валидный — request.user=None, request.auth=ServiceAccount.
        Если токен не предъявлен — возвращает None (пусть отработают другие).
        Если токен предъявлен, но невалидный — AuthenticationFailed.
        """

        keyword = "Bearer"

        def authenticate(self, request):
            plaintext = _extract_bearer(request)
            if not plaintext:
                return None

            token = ServiceAccountToken.verify(plaintext)
            if token is None:
                raise AuthenticationFailed("invalid service token")

            try:
                token.touch()
            except Exception:
                pass

            return (None, token.account)

        def authenticate_header(self, request):
            return self.keyword

except ImportError:
    ServiceAccountTokenAuthentication = None  # type: ignore