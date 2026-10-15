from django.apps import AppConfig


class SecretsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.secrets"
    verbose_name = "Секреты"

    def ready(self):
        import atexit

        from .keepass_helpers import shutdown_snapshot_pool
        
        atexit.register(shutdown_snapshot_pool, False)