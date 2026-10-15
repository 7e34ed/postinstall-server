from django.contrib import admin
from django.utils.html import format_html
from unfold.admin import ModelAdmin

from .models import SecretAccessLog, SecretsMigration, ServerKey
from .runtime import runtime


@admin.register(SecretsMigration)
class SecretsMigrationAdmin(ModelAdmin):
    list_display = ("id_short", "source_backend", "target_backend",
                    "status", "progress_short", "started_at", "finished_at")
    list_filter = ("status", "source_backend", "target_backend")
    readonly_fields = [f.name for f in SecretsMigration._meta.fields]
    search_fields = ("id", "last_path")
    date_hierarchy = "started_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.display(description="ID")
    def id_short(self, obj):
        return str(obj.id)[:8]

    @admin.display(description="Прогресс")
    def progress_short(self, obj):
        return f"{obj.done + obj.skipped + obj.failed}/{obj.total}"


@admin.register(ServerKey)
class ServerKeyAdmin(ModelAdmin):
    list_display = ("version", "updated_at", "rotated_at")
    readonly_fields = ("salt", "blob", "version", "rotated_at",
                       "rotated_by", "created_at", "updated_at",
                       "backend_link")

    def backend_link(self, obj):
        return format_html(
            '<a class="button" href="/admin/secrets/backend/">'
            'Управление backend →</a>'
        )
    backend_link.short_description = "Backend"

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

@admin.register(SecretAccessLog)
class SecretAccessLogAdmin(ModelAdmin):
    list_display = ("created_at", "action", "path", "key", "user", "ip",
                    "success")
    list_filter = ("action", "success")
    search_fields = ("path", "key", "user__username", "error")
    readonly_fields = [f.name for f in SecretAccessLog._meta.fields]
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False