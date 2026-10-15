from django.contrib import admin
from unfold.admin import ModelAdmin

from .models import (
    AuditExportCursor,
    AuditSeal,
    AuditSigningKey,
    AuditVerifyRun,
)


@admin.register(AuditSigningKey)
class AuditSigningKeyAdmin(ModelAdmin):
    list_display = ("created_at", "is_active", "description")
    list_filter = ("is_active",)
    readonly_fields = [f.name for f in AuditSigningKey._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditSeal)
class AuditSealAdmin(ModelAdmin):
    list_display = ("source", "first_id", "last_id", "count",
                    "sealed_at", "key")
    list_filter = ("source",)
    readonly_fields = [f.name for f in AuditSeal._meta.fields]
    date_hierarchy = "sealed_at"

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditExportCursor)
class AuditExportCursorAdmin(ModelAdmin):
    list_display = ("source", "target", "last_exported_id",
                    "last_exported_at")
    list_filter = ("source", "target")
    readonly_fields = ("created_at", "updated_at")


@admin.register(AuditVerifyRun)
class AuditVerifyRunAdmin(ModelAdmin):
    list_display = ("source", "status", "checked_records",
                    "checked_seals", "first_broken_id", "started_at")
    list_filter = ("source", "status")
    readonly_fields = [f.name for f in AuditVerifyRun._meta.fields]
    date_hierarchy = "started_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False