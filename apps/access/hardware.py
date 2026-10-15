"""Определение наличия hardware-фактора у пользователя."""
from __future__ import annotations


def has_hardware_factor(user) -> bool:
    """WebAuthn, клиентский сертификат или Rutoken."""
    if user is None or not user.is_authenticated:
        return False

    try:
        from allauth.mfa.models import Authenticator
        
        if Authenticator.objects.filter(
            user=user, type="webauthn",
        ).exists():
            return True
    except Exception:
        pass

    from .models import UserCertificate
    return UserCertificate.objects.filter(
        user=user, is_active=True,
    ).exists()