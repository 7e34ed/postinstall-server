# хелперы, не фикстуры

# tests/helpers.py
"""Хелперы для тестов access."""

def add_totp(user):
    from allauth.mfa.models import Authenticator
    return Authenticator.objects.create(
        user=user, type=Authenticator.Type.TOTP, data={},
    )

def add_role(user, role, scope_type="global", scope_id=0):
    from apps.access.models import RoleAssignment
    return RoleAssignment.objects.create(
        user=user, role=role, scope_type=scope_type, scope_id=scope_id,
    )