from django.contrib import admin
from unfold.admin import ModelAdmin

from .models import LDAPHostMap, LDAPSyncRun


@admin.register(LDAPSyncRun)
class LDAPSyncRunAdmin(ModelAdmin):
    list_display = ("started_at", "domain", "kind", "status",
                    "found", "created", "updated", "failed")
    list_filter = ("kind", "status", "domain")
    readonly_fields = [f.name for f in LDAPSyncRun._meta.fields]
    date_hierarchy = "started_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(LDAPHostMap)
class LDAPHostMapAdmin(ModelAdmin):
    list_display = ("ad_sam", "ad_dns", "host", "domain",
                    "is_active_in_ad", "last_seen_in_ad")
    list_filter = ("domain", "is_active_in_ad")
    search_fields = ("ad_sam", "ad_dns", "host__hostname")
    readonly_fields = ("created_at", "updated_at")