"""Аудит enrollment/disable TOTP через allauth.mfa."""
from __future__ import annotations

from django.dispatch import receiver
from loguru import logger

try:
    from allauth.mfa.signals import (
        authenticator_created,
        authenticator_deleted,
    )
except ImportError:
    authenticator_created = None
    authenticator_deleted = None

from .models import AuthAuditLog, log_auth_event

if authenticator_created is not None:

    @receiver(authenticator_created)
    def _log_mfa_enrolled(sender, request, user, authenticator, **kwargs):
        log_auth_event(
            AuthAuditLog.Event.MFA_ENROLLED,
            user=user,
            detail={"type": str(getattr(authenticator, "type", "unknown"))},
        )
        logger.info(f"access: MFA enrolled for {user.username}")

    @receiver(authenticator_deleted)
    def _log_mfa_disabled(sender, request, user, authenticator, **kwargs):
        log_auth_event(
            AuthAuditLog.Event.MFA_DISABLED,
            user=user,
            detail={"type": str(getattr(authenticator, "type", "unknown"))},
        )
        logger.info(f"access: MFA disabled for {user.username}")