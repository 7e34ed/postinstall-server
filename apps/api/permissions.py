from rest_framework.permissions import BasePermission

from apps.deploy.models import Agent


class IsAgent(BasePermission):
    """Пускает только аутентифицированного агента."""

    message = "Требуется аутентификация агента."

    def has_permission(self, request, view):
        return isinstance(request.auth, Agent)