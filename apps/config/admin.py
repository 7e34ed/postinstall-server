from django.contrib import admin
from unfold.admin import ModelAdmin, TabularInline

from .models import (
    Certificate,
    ConfigProfile,
    ConfigRevision,
    HostExtraProfile,
    HostSetProfile,
    Package,
    Repository,
)


@admin.register(Repository)
class RepositoryAdmin(ModelAdmin):
    list_display = ("name", "platform", "url", "priority", "is_active")
    list_filter = ("platform", "is_active")
    search_fields = ("name", "url")


@admin.register(Certificate)
class CertificateAdmin(ModelAdmin):
    list_display = ("name", "is_active", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("name",)
    readonly_fields = ("content_b64",)


@admin.register(Package)
class PackageAdmin(ModelAdmin):
    list_display = ("name", "platform", "url", "is_active")
    list_filter = ("platform", "is_active")
    search_fields = ("name", "url")


class HostSetProfileInline(TabularInline):
    model = HostSetProfile
    fk_name = "host_set"
    extra = 0
    autocomplete_fields = ("profile",)
    ordering = ("order",)


class HostExtraProfileInline(TabularInline):
    model = HostExtraProfile
    fk_name = "host"
    extra = 0
    autocomplete_fields = ("profile",)
    ordering = ("order",)


class ConfigRevisionInline(TabularInline):
    model = ConfigRevision
    extra = 0
    fields = ("version", "created_at", "created_by", "comment")
    readonly_fields = ("version", "created_at", "created_by")
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(ConfigProfile)
class ConfigProfileAdmin(ModelAdmin):
    list_display = ("name", "slug", "platform", "version", "is_active",
                    "updated_at")
    list_filter = ("platform", "is_active")
    search_fields = ("name", "slug", "description")
    prepopulated_fields = {"slug": ("name",)}
    filter_horizontal = ("repositories", "certificates", "package_installs")
    readonly_fields = ("version",)
    inlines = [ConfigRevisionInline]

    fieldsets = (
        ("Основное", {
            "fields": ("name", "slug", "description", "platform",
                       "is_active", "tags"),
        }),
        ("Композиция", {
            "fields": ("extra_ports", "jails", "packages",
                       "repositories", "certificates", "package_installs"),
        }),
        ("Скрипт и оверрайды", {
            "fields": ("postinstall_script", "settings", "hardening"),
        }),
        ("Версия", {
            "fields": ("version",),
        }),
    )


@admin.register(ConfigRevision)
class ConfigRevisionAdmin(ModelAdmin):
    list_display = ("profile", "version", "created_at", "created_by")
    list_filter = ("profile",)
    readonly_fields = ("profile", "version", "snapshot", "created_at",
                       "created_by")
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(HostSetProfile)
class HostSetProfileAdmin(ModelAdmin):
    list_display = ("host_set", "profile", "order")
    list_filter = ("host_set__domain",)
    autocomplete_fields = ("host_set", "profile")


@admin.register(HostExtraProfile)
class HostExtraProfileAdmin(ModelAdmin):
    list_display = ("host", "profile", "order")
    list_filter = ("host__domain",)
    autocomplete_fields = ("host", "profile")