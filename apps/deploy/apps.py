from django.apps import AppConfig


class DeployConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.deploy"
    verbose_name = "Развёртывание"

    def ready(self):
        from . import signals  # noqa: F401