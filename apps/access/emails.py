"""Отправка писем для инвайтов."""
from __future__ import annotations

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from loguru import logger

from .models import Invitation


def _build_accept_url(invitation: Invitation, token: str) -> str:
    path = reverse("access:invite-accept", args=[token])
    base = getattr(settings, "ACCESS_PUBLIC_BASE_URL", "").rstrip("/")
    if base:
        return f"{base}{path}"
    return path


def send_invitation_email(
    invitation: Invitation, token: str, *, request=None,
) -> bool:
    """Отправить письмо приглашённому.

    Тема и тело — из шаблонов templates/access/emails/invite_*.{txt,html}.
    Возвращает True при успешной отправке.
    """
    accept_url = _build_accept_url(invitation, token)
    expires_at = invitation.expires_at
    scope_type = invitation.scope_type
    scope_id = invitation.scope_id

    scope_label = _scope_label(scope_type, scope_id)

    context = {
        "invitation": invitation,
        "accept_url": accept_url,
        "expires_at": expires_at,
        "scope_label": scope_label,
        "role": invitation.role,
        "site_name": getattr(settings, "SITE_NAME", "postinstall-server"),
        "invited_by": invitation.invited_by,
    }

    subject = f"Приглашение в {context['site_name']}"
    body_txt = render_to_string("access/emails/invite.txt", context)
    body_html = render_to_string("access/emails/invite.html", context)

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL",
                         "noreply@localhost")
    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=body_txt,
            from_email=from_email,
            to=[invitation.email],
        )
        msg.attach_alternative(body_html, "text/html")
        msg.send(fail_silently=False)
        logger.info(f"invitation email sent to {invitation.email}")
        return True
    except Exception as exc:
        logger.error(f"invitation email failed: {exc}")
        return False


def send_invitation_approved_email(invitation: Invitation) -> bool:
    """Второе письмо — если инвайт прошёл consensus.

    Обычно первое письмо уходит только после approve. Но если admin
    создаёт инвайт и мы хотим уведомить — используем эту функцию.
    """
    # для OPERATOR/VIEWER письмо уходит сразу при создании
    # для ADMIN/SUPERVISOR — после второго approve
    return False


def _scope_label(scope_type: str, scope_id: int) -> str:
    if scope_type == "global":
        return "Глобально"
    try:
        if scope_type == "domain":
            from apps.inventory.models import Domain
            obj = Domain.objects.filter(pk=scope_id).first()
            return f"Домен {obj.name}" if obj else f"domain:{scope_id}"
        if scope_type == "host_set":
            from apps.inventory.models import HostSet
            obj = HostSet.objects.filter(pk=scope_id).first()
            return f"Набор {obj}" if obj else f"host_set:{scope_id}"
        if scope_type == "host":
            from apps.inventory.models import Host
            obj = Host.objects.filter(pk=scope_id).first()
            return f"Хост {obj.hostname}" if obj else f"host:{scope_id}"
    except Exception:
        pass
    return f"{scope_type}:{scope_id}"