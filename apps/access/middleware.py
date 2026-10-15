from __future__ import annotations

from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from loguru import logger

from .models import RoleChangeNotice, SuperuserBootstrap, UserActivity

SETUP_EXEMPT_PREFIXES = (
    "/accounts/",
    "/static/",
    "/media/",
    "/admin/login/",
    "/admin/logout/",
    "/access/setup/",
    "/access/invite/",
    "/api/v1/health",
    "/favicon",
)


ROLE_NOTICE_EXEMPT_PREFIXES = (
    "/accounts/",
    "/static/",
    "/media/",
    "/admin/logout/",
    "/admin/login/",
    "/access/roles-changed/",
    "/access/invite/",
    "/api/v1/health",
    "/favicon",
)


MFA_ENFORCE_EXEMPT_PREFIXES = (
    "/static/",
    "/media/",
    "/accounts/",              # весь allauth (login, logout, 2fa)
    "/admin/login/",
    "/admin/logout/",
    "/access/setup/",
    "/access/invite/",
    "/access/roles-changed/",
    "/api/v1/health",
    "/api/v1/agent/",          # агенты не пользователи
    "/favicon",
)


AAL_EXEMPT_PREFIXES = (
    "/static/",
    "/media/",
    "/accounts/",              # allauth (login, 2fa)
    "/admin/login/",
    "/admin/logout/",
    "/admin/secrets/unlock/",
    "/access/setup/",
    "/access/invite/",
    "/access/roles-changed/",
    "/api/v1/health",
    "/api/v1/agent/",
    "/favicon",
)


class AalEnforcementMiddleware:
    """Если URL требует AAL выше, чем есть в сессии — редирект на reauth.

    Работает после AuthMiddleware, до других проверок.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .aal import requirement_for_path
        from .session_aal import current_aal, is_aal_fresh

        path = request.path
        if any(path.startswith(p) for p in AAL_EXEMPT_PREFIXES):
            return self.get_response(request)

        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return self.get_response(request)

        # if user and user.is_authenticated:
        #     # Break-glass — пропускаем, у него уже AAL3
        #     from .models import BreakGlassAccount
        #     acc = BreakGlassAccount.get()
        #     if acc and acc.user_id == user.pk:
        #         return self.get_response(request)


        if user.is_superuser:
            return self.get_response(request)

        # Break-glass-пользователь всегда проходит: у него AAL3
        try:
            from .models import BreakGlassAccount
            
            acc = BreakGlassAccount.get()
            if acc and acc.user_id == user.pk and acc.is_currently_active():
                return self.get_response(request)
        except Exception:
            pass

        required = requirement_for_path(path)
        if required is None:
            return self.get_response(request)

        have = current_aal(request)
        if have < required:
            from urllib.parse import quote

            from django.shortcuts import redirect
            from django.urls import reverse

            cb = reverse("access:reauth-success")
            final_next = request.get_full_path()
            callback_url = (
                f"{cb}?final_next={quote(final_next, safe='')}"
                f"&required={int(required)}"
            )
            mfa_url = reverse("mfa_reauthenticate")
            return redirect(
                f"{mfa_url}?next={quote(callback_url, safe='')}"
            )

        if not is_aal_fresh(request):
            from django.shortcuts import redirect
            from django.urls import reverse

            url = reverse("mfa_reauthenticate")
            return redirect(
                f"{url}?next={request.get_full_path()}"
                f"&required={int(required)}&expired=1"
            )

        return self.get_response(request)


class SetupPhaseMiddleware:
    """Пока setup не завершён — все запросы уходят на мастер настройки."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        if any(path.startswith(p) for p in SETUP_EXEMPT_PREFIXES):
            return self.get_response(request)

        bootstrap = SuperuserBootstrap.get()
        if bootstrap.is_setup_complete:
            return self.get_response(request)

        # Setup-фаза: редирект на мастер
        setup_url = reverse("access:setup")
        if path == setup_url:
            return self.get_response(request)

        return HttpResponseRedirect(setup_url)


class RoleChangeNoticeMiddleware:
    """Если у пользователя есть неотвеченные RoleChangeNotice —
    навязчиво показываем экран подтверждения.
    """

    THROTTLE_SECONDS = 60   # как часто обновлять last_activity_at

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)

        if user and user.is_authenticated:
            self._touch_activity(user)

            path = request.path
            if not any(path.startswith(p) for p in ROLE_NOTICE_EXEMPT_PREFIXES):
                has_notice = RoleChangeNotice.objects.filter(
                    user=user, acknowledged_at__isnull=True,
                ).exists()
                if has_notice:
                    return HttpResponseRedirect(reverse("access:roles-changed"))

        return self.get_response(request)

    @staticmethod
    def _touch_activity(user) -> None:
        try:
            activity, _ = UserActivity.objects.get_or_create(user=user)
            now = timezone.now()
            if (
                activity.last_activity_at is None
                or (now - activity.last_activity_at).total_seconds()
                > RoleChangeNoticeMiddleware.THROTTLE_SECONDS
            ):
                activity.last_activity_at = now
                activity.save(update_fields=["last_activity_at"])
        except Exception:
            logger.exception("access: touch activity failed")\


class MfaEnforcementMiddleware:
    """Если у пользователя роль требует MFA, а MFA не настроен — редирект на enrollment."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return self.get_response(request)

        path = request.path
        if any(path.startswith(p) for p in MFA_ENFORCE_EXEMPT_PREFIXES):
            return self.get_response(request)

        if not self._mfa_enabled():
            return self.get_response(request)
        if user.is_superuser:
            return self.get_response(request)
        if not self._user_role_requires_mfa(user):
            return self.get_response(request)
        if self._user_has_totp(user):
            return self.get_response(request)

        # Grace period
        grace_hours = self._grace_period_hours()
        if grace_hours > 0:
            first_seen = self._user_first_seen(user)
            if first_seen is None:
                self._mark_first_seen(user)
                first_seen = timezone.now()
            delta = timezone.now() - first_seen
            if delta.total_seconds() < grace_hours * 3600:
                from django.contrib import messages

                if not request.session.get("mfa_warning_shown"):
                    messages.warning(
                        request,
                        f"Настройте MFA — иначе доступ ограничится через {grace_hours} ч.",
                    )
                    request.session["mfa_warning_shown"] = True
                return self.get_response(request)

        from django.shortcuts import redirect

        return redirect("/accounts/2fa/totp/activate/")

    def _mfa_enabled(self) -> bool:
        try:
            from constance import config

            return bool(config.MFA_ENABLED)
        except Exception:
            return True

    def _user_role_requires_mfa(self, user) -> bool:
        try:
            from constance import config

        except Exception:
            return False

        try:
            from apps.access.permissions import is_supervisor
            if is_supervisor(user) and config.MFA_REQUIRED_FOR_SUPERVISOR:
                return True
        except Exception:
            pass

        from apps.access.models import RoleAssignment
        from apps.access.roles import Role

        now = timezone.now()
        for ra in RoleAssignment.objects.filter(user=user, revoked_at__isnull=True):
            if ra.valid_until and ra.valid_until < now:
                continue
            if ra.role == Role.ADMIN.value and config.MFA_REQUIRED_FOR_ADMIN:
                return True
            if ra.role == Role.OPERATOR.value and config.MFA_REQUIRED_FOR_OPERATOR:
                return True
            if ra.role == Role.AUDITOR.value and config.MFA_REQUIRED_FOR_AUDITOR:
                return True
        return False

    def _user_has_totp(self, user) -> bool:
        try:
            from allauth.mfa.models import Authenticator

            return Authenticator.objects.filter(
                user=user, type=Authenticator.Type.TOTP,
            ).exists()
        except Exception:
            return False

    def _grace_period_hours(self) -> int:
        try:
            from constance import config

            return int(config.MFA_GRACE_PERIOD_HOURS or 0)
        except Exception:
            return 0

    def _user_first_seen(self, user):
        from .models import UserActivity
        try:
            return UserActivity.objects.get(user=user).mfa_first_seen_at
        except UserActivity.DoesNotExist:
            return None

    def _mark_first_seen(self, user) -> None:
        from .models import UserActivity
        act, _ = UserActivity.objects.get_or_create(user=user)
        if act.mfa_first_seen_at is None:
            act.mfa_first_seen_at = timezone.now()
            act.save(update_fields=["mfa_first_seen_at"])


class IPAllowlistMiddleware:
    """Проверяет IP против allowlist.

    Если IP не подходит — 403 и запись в AuthAuditLog.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return self.get_response(request)

        from apps.core.utils import get_client_ip

        from .ip_allowlist import check_ip
        from .models import AuthAuditLog, log_auth_event

        ok, reason = check_ip(request, user)
        if not ok:
            log_auth_event(
                AuthAuditLog.Event.IP_DENIED,
                user=user, ip=get_client_ip(request),
                success=False, error=reason,
                detail={"path": request.path},
            )
            logger.warning(
                f"access: IP denied for {user.username}: {reason}"
            )
            from django.http import HttpResponseForbidden
            from django.template.loader import render_to_string
            
            html = render_to_string("access/ip_denied.html", {
                "user": user, "reason": reason,
            }, request=request)
            return HttpResponseForbidden(html)

        return self.get_response(request)