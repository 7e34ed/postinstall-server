from django.contrib import admin
from unfold.admin import ModelAdmin

from .models import Agent, BulkDeployment, Deployment, DeploymentReport, ServerIdentity


@admin.register(ServerIdentity)
class ServerIdentityAdmin(ModelAdmin):
    list_display = ("created_at", "updated_at")
    readonly_fields = (
        "pubkey_ed25519", "privkey_ed25519", "pubkey_x25519", "privkey_x25519",
        "created_at", "updated_at",
    )

    def has_add_permission(self, request):
        return not ServerIdentity.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Agent)
class AgentAdmin(ModelAdmin):
    list_display = ("host", "agent_id", "version", "is_active",
                    "last_seen_at", "registered_at")
    list_filter = ("is_active", "host__domain")
    search_fields = ("host__hostname", "agent_id", "version")
    readonly_fields = ("agent_id", "registered_at", "last_seen_at", "last_seen_ip")
    autocomplete_fields = ("host",)


@admin.register(Deployment)
class DeploymentAdmin(ModelAdmin):
    list_display = ("id", "host", "status", "priority", "created_at",
                    "dispatched_at", "finished_at")
    list_filter = ("status", "host__domain")
    search_fields = ("id", "host__hostname")
    readonly_fields = ("rendered_config", "dispatched_at", "finished_at")
    autocomplete_fields = ("host", "created_by")
    date_hierarchy = "created_at"


@admin.register(DeploymentReport)
class DeploymentReportAdmin(ModelAdmin):
    list_display = ("deployment", "status", "started_at", "finished_at",
                    "agent_version")
    list_filter = ("status", "deployment__host__domain")
    readonly_fields = ("raw", "modules", "hardening")
    autocomplete_fields = ("deployment",)


@admin.register(BulkDeployment)
class BulkDeploymentAdmin(ModelAdmin):
    list_display = ("name", "status", "total", "succeeded", "failed",
                    "cancelled_count", "created_at")
    list_filter = ("status",)
    search_fields = ("name", "id")
    readonly_fields = ("total", "succeeded", "failed", "cancelled_count",
                       "status", "created_by", "created_at", "updated_at")
    date_hierarchy = "created_at"