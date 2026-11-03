from django.apps import AppConfig


class AccessConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.access"
    verbose_name = "Доступ и роли"

    def ready(self):
        from apps.core.decorators import register_rate_limit_auditor
        from apps.core.permissions import (
            register_aal_requirement,
            register_active_roles,
            register_object_checkers,
            register_supervisor_checker,
            register_user_max_aal,
        )

        from .aal import requirement_for_action, user_max_aal
        from .audit import rate_limit_auditor
        from .permissions import (
            active_roles,
            is_supervisor,
            user_can_deploy,
            user_can_view_object,
        )

        register_supervisor_checker(is_supervisor)
        register_rate_limit_auditor(rate_limit_auditor)
        register_aal_requirement(lambda a: int(requirement_for_action(a)))
        register_active_roles(lambda u: {ra.role for ra in active_roles(u)})
        register_user_max_aal(user_max_aal)
        register_object_checkers(user_can_view_object, user_can_deploy)

        from . import (
            mfa_signals,  # noqa: F401
            signals,  # noqa: F401
        )