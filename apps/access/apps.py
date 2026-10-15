from django.apps import AppConfig


class AccessConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.access"
    verbose_name = "Доступ и роли"

    def ready(self):
        # Регистрируем реализацию is_supervisor в core
        from apps.core.permissions import register_supervisor_checker

        from .permissions import is_supervisor
        register_supervisor_checker(is_supervisor)

    
        from . import (
            mfa_signals,  # noqa: F401
            signals,  # noqa: F401
        )
