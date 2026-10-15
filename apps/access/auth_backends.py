"""Django auth backend для аутентификации через RADIUS / Aladdin HOTP.

Логика маршрутизации:

  User.auth_source == "radius"  → только RadiusBackend проверяет.
  User.auth_source == "local"   → RadiusBackend отказывает, работает ModelBackend.
  superuser                      → всегда через ModelBackend.

Если пользователь не найден в БД — отказ. Никакого auto-provision,
доступ только по инвайту.

При успехе:
  * AAL сессии поднимается до AAL2 (RADIUS уже даёт password+OTP);
  * пишется AuthAuditLog (LOGIN_SUCCESS с method=radius).

Параметры соединения берутся из constance. Если RADIUS недоступен —
fail-closed (отказ), кроме случая AUTH_RADIUS_FAIL_OPEN=True (только
для break-glass, не рекомендуется).
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend as DjangoModelBackend
from loguru import logger

from .radius_client import (
    RadiusConfig,
    RadiusError,
    RadiusResult,
    RadiusTimeout,
    RadiusUnreachable,
    authenticate,
)


def _radius_config() -> RadiusConfig | None:
    try:
        from constance import config

    except Exception:
        return None

    if not getattr(config, "AUTH_RADIUS_ENABLED", False):
        return None

    host = (getattr(config, "AUTH_RADIUS_HOST", "") or "").strip()
    secret = getattr(config, "AUTH_RADIUS_SECRET", "") or ""
    if not host or not secret:
        logger.warning(
            "radius: включён, но не заданы AUTH_RADIUS_HOST / AUTH_RADIUS_SECRET"
        )
        return None

    return RadiusConfig(
        host=host,
        port=int(getattr(config, "AUTH_RADIUS_PORT", 1812) or 1812),
        secret=secret,
        nas_identifier=(getattr(config, "AUTH_RADIUS_NAS_ID", "") or "").strip(),
        timeout=int(getattr(config, "AUTH_RADIUS_TIMEOUT", 3) or 3),
        retries=int(getattr(config, "AUTH_RADIUS_RETRIES", 2) or 2),
    )


def _fail_open() -> bool:
    try:
        from constance import config
        
        return bool(config.AUTH_RADIUS_FAIL_OPEN)
    except Exception:
        return False


class LocalOnlyBackend(DjangoModelBackend):
    """ModelBackend, который отказывает пользователям auth_source=radius."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username=username,
                                    password=password, **kwargs)
        if user is None:
            return None
        from .radius_utils import get_auth_source
        if get_auth_source(user) == "radius":
            logger.warning(
                f"local: {username} пытается зайти через ModelBackend, "
                f"но auth_source=radius"
            )
            return None
        return user


class RadiusBackend:
    """Django auth backend.

    Не путать с allauth. allauth — фреймворк для login-flow, а backend —
    конкретный механизм проверки credentials. Они совместимы: allauth
    вызывает django.contrib.auth.authenticate(), а тот перебирает
    AUTHENTICATION_BACKENDS.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password:
            return None

        cfg = _radius_config()
        if cfg is None:
            return None

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        # Маршрутизация по auth_source
               
        # source = getattr(user, "auth_source", "local")
        from .radius_utils import get_auth_source
        source = get_auth_source(user)

        if source != "radius":
            # Локальный пользователь — Radius не проверяет
            return None

        if not user.is_active:
            logger.warning(
                f"radius: user {username} inactive, отказ"
            )
            return None

        try:
            result = authenticate(cfg, username=username, password=password)
        except RadiusTimeout:
            if _fail_open():
                logger.warning(
                    f"radius: timeout для {username}, "
                    f"fail-open разрешён — пропускаем через локальный backend"
                )
                return None   # fallback к следующему backend
            logger.error(
                f"radius: timeout для {username}, fail-closed"
            )
            return None
        except (RadiusUnreachable, RadiusError) as exc:
            logger.error(f"radius: ошибка для {username}: {exc}")
            return None

        if not result.accepted:
            logger.info(
                f"radius: отказ для {username}: {result.message or 'reject'}"
            )
            return None

        return user

    def get_user(self, user_id):
        from django.contrib.auth import get_user_model as _get

        User = _get()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


# --- Хелперы для view / тестов ---

def test_connection(cfg: RadiusConfig, *, username: str = "radius-test",
                    password: str = "wrong-password") -> RadiusResult | None:
    """Проверка доступности RADIUS. Возвращает результат или None при ошибке."""
    try:
        return authenticate(cfg, username=username, password=password)
    except (RadiusTimeout, RadiusUnreachable, RadiusError) as exc:
        logger.warning(f"radius: test_connection failed: {exc}")
        return None


def build_config_from_constance() -> RadiusConfig | None:
    """Для UI health-check."""
    return _radius_config()