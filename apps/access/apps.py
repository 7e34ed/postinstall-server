from django.apps import AppConfig


class AccessConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.access"
    verbose_name = "Доступ и роли"

    def ready(self):
        from apps.core.decorators import register_rate_limit_auditor
        from apps.core.permissions import register_supervisor_checker

        from .audit import rate_limit_auditor
        from .permissions import is_supervisor

        register_supervisor_checker(is_supervisor)
        register_rate_limit_auditor(rate_limit_auditor)

        from . import (
            mfa_signals,  # noqa: F401
            signals,  # noqa: F401
        )