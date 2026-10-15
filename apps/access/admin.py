from django.contrib import admin
from unfold.admin import ModelAdmin

from .models import (
    AuthAuditLog,
    DeputyAssignment,
    DirectRoleAssignment,
    Invitation,
    RoleAssignment,
    RoleChangeNotice,
    SuperuserBootstrap,
    UserActivity,
    UserAuthSettings,
    UserCertificate,
)


class UserAuthSettingsInline(admin.StackedInline):
    model = UserAuthSettings
    extra = 0
    can_delete = False


@admin.register(DirectRoleAssignment)
class DirectRoleAssignmentAdmin(ModelAdmin):
    list_display = ("target_user", "role", "scope_type", "scope_id",
                    "status", "initiated_by", "executed_at", "created_at")
    list_filter = ("status", "role")
    search_fields = ("target_user__username", "initiated_by__username")
    readonly_fields = ("created_at", "updated_at", "approval1_at",
                       "approval2_at", "executed_at")

@admin.register(SuperuserBootstrap)
class SuperuserBootstrapAdmin(ModelAdmin):
    list_display = ("id", "is_setup_complete", "setup_started_at",
                    "setup_completed_at", "initial_superuser")
    readonly_fields = [f.name for f in SuperuserBootstrap._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(RoleAssignment)
class RoleAssignmentAdmin(ModelAdmin):
    list_display = ("user", "role", "scope_type", "scope_id",
                    "valid_until", "granted_at", "revoked_at")
    list_filter = ("role", "scope_type", "revoked_at")
    search_fields = ("user__username", "user__email")
    readonly_fields = ("granted_at",)
    date_hierarchy = "granted_at"


@admin.register(Invitation)
class InvitationAdmin(ModelAdmin):
    list_display = ("email", "role", "scope_type", "scope_id",
                    "status", "expires_at", "invited_by", "created_at")
    list_filter = ("status", "role")
    search_fields = ("email", "id")
    readonly_fields = ("id", "token_hash", "created_at", "updated_at",
                       "approval1_at", "approval2_at", "accepted_at")
    date_hierarchy = "created_at"


@admin.register(RoleChangeNotice)
class RoleChangeNoticeAdmin(ModelAdmin):
    list_display = ("user", "created_at", "acknowledged_at", "reason")
    list_filter = ("acknowledged_at",)
    search_fields = ("user__username",)
    readonly_fields = [f.name for f in RoleChangeNotice._meta.fields]


@admin.register(DeputyAssignment)
class DeputyAssignmentAdmin(ModelAdmin):
    list_display = ("principal", "deputy", "kind", "is_active",
                    "valid_from", "valid_until")
    list_filter = ("kind", "is_active")
    search_fields = ("principal__username", "deputy__username")


@admin.register(UserActivity)
class UserActivityAdmin(ModelAdmin):
    list_display = ("user", "last_activity_at")
    search_fields = ("user__username",)


@admin.register(UserCertificate)
class UserCertificateAdmin(ModelAdmin):
    list_display = ("user", "label", "fingerprint_sha256", "is_active",
                    "valid_to", "created_at")
    list_filter = ("is_active",)
    search_fields = ("user__username", "fingerprint_sha256", "subject_dn")
    readonly_fields = ("fingerprint_sha256", "created_at")


@admin.register(AuthAuditLog)
class AuthAuditLogAdmin(ModelAdmin):
    list_display = ("created_at", "event", "user", "target_user", "ip",
                    "success")
    list_filter = ("event", "success")
    search_fields = ("user__username", "target_user__username", "ip")
    readonly_fields = [f.name for f in AuthAuditLog._meta.fields]
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserAuthSettings)
class UserAuthSettingsAdmin(ModelAdmin):
    list_display = ("user", "auth_source", "radius_username", "updated_at")
    list_filter = ("auth_source",)
    search_fields = ("user__username", "user__email", "radius_username")
    autocomplete_fields = ("user",)
    readonly_fields = ("created_at", "updated_at")