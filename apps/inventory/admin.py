from django.contrib import admin
from guardian.admin import GuardedModelAdmin
from unfold.admin import ModelAdmin, TabularInline

from .models import Domain, Host, HostSet


@admin.register(Domain)
class DomainAdmin(ModelAdmin, GuardedModelAdmin):
    list_display = ("name", "description", "ldap_sync_enabled",
                    "ldap_last_sync_at")
    search_fields = ("name",)
    list_filter = ("ldap_sync_enabled",)
    autocomplete_fields = ("domain_join_secret",)


class HostInline(TabularInline):
    model = Host
    extra = 0
    fields = ("hostname", "ip_primary", "managed", "agent_last_seen_at")
    readonly_fields = ("agent_last_seen_at",)
    show_change_link = True


@admin.register(HostSet)
class HostSetAdmin(ModelAdmin, GuardedModelAdmin):
    list_display = ("name", "domain", "platform", "hosts_count")
    list_filter = ("domain", "platform")
    search_fields = ("name",)
    inlines = [HostInline]

    @admin.display(description="Хостов")
    def hosts_count(self, obj):
        return obj.hosts.count()


@admin.register(Host)
class HostAdmin(ModelAdmin, GuardedModelAdmin):
    list_display = ("hostname", "domain", "host_set", "ip_primary",
                    "managed", "agent_last_seen_at")
    list_filter = ("domain", "host_set", "managed", "source")
    search_fields = ("hostname", "fqdn", "ip_primary")
    readonly_fields = ("agent_registered_at", "agent_last_seen_at",
                       "agent_version")
    autocomplete_fields = ("domain", "host_set")
