"""Аудит enrollment/disable TOTP через allauth.mfa."""
# apps/access/mfa_signals.py
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from loguru import logger

from .models import AuthAuditLog, log_auth_event


@receiver(post_save, sender="mfa.Authenticator")
def _log_mfa_enrolled(sender, instance, created, **kwargs):
    if not created:
        return
    log_auth_event(
        AuthAuditLog.Event.MFA_ENROLLED,
        user=instance.user,
        detail={"type": str(getattr(instance, "type", "unknown"))},
    )
    logger.info(f"access: MFA enrolled for {instance.user.username}")


@receiver(post_delete, sender="mfa.Authenticator")
def _log_mfa_disabled(sender, instance, **kwargs):
    log_auth_event(
        AuthAuditLog.Event.MFA_DISABLED,
        user=instance.user,
        detail={"type": str(getattr(instance, "type", "unknown"))},
    )