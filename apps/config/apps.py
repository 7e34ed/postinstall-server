from django.apps import AppConfig


class ConfigAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.config"
    verbose_name = "Конфигурации"

    def ready(self):
        from . import signals  # noqa: F401