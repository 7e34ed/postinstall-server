from django.apps import AppConfig


class InventoryConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.inventory"
    verbose_name = "Инвентарь"

    def ready(self):
        from apps.core.utils import register_scope_resolver

        from .scopes import _resolve_scope_object
        
        register_scope_resolver(_resolve_scope_object)