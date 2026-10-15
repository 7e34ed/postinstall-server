from django.urls import path

from . import admin_views as _admin
from . import views

app_name = "access"

urlpatterns = [
     path("setup/", views.setup_view, name="setup"),
     path("roles-changed/", views.roles_changed_view, name="roles-changed"),
     path("invite/<str:token>/", views.invite_accept, name="invite-accept"),

     # UI инвайтов
     path("invites/", _admin.invites_list, name="invites-list"),
     path("invites/new/", _admin.invite_create, name="invite-create"),
     path("invites/<uuid:pk>/approve/", _admin.invite_approve,
          name="invite-approve"),
     path("invites/<uuid:pk>/revoke/", _admin.invite_revoke,
          name="invite-revoke"),
     path("invites/<uuid:pk>/resend/", _admin.invite_resend,
          name="invite-resend"),

     # UI ролей
     path("roles/", _admin.roles_list, name="roles-list"),
     path("roles/assign/", _admin.role_assign, name="role-assign"),
     path("roles/<int:pk>/revoke/", _admin.role_revoke, name="role-revoke"),
     path("direct/<uuid:pk>/approve/", _admin.direct_approve,
          name="direct-approve"),

     # аутентификация
     path("reauth/success/", views.reauth_success, name="reauth-success"),
     path("security/", _admin.security_center, name="my-security"),
     path("high-security/", _admin.high_security_page,
          name="high-security"),

     # клиентские mTLS 
     path("security/certificates/", _admin.certificates_list,
          name="certificates-list"),
     path("security/certificates/<int:pk>/revoke/",
          _admin.certificate_revoke,
          name="certificate-revoke"),
     path("radius/", _admin.radius_page, name="radius"),
     path("users/<int:user_id>/auth-source/", _admin.user_set_auth_source,
          name="user-auth-source"),
     
     # Аварийка, использовать случае отсутствия живых супервизоров, 
     # включается на 24 часа по-умолчанию
     path("break-glass/", _admin.break_glass_page, name="break-glass"),
     path("access-review/", _admin.access_review_page, name="access-review"),
     path("access-review/<uuid:run_id>/", _admin.access_review_detail,
          name="access-review-detail"),
     path("recovery-kit/<str:filename>/", views.recovery_kit_download,
          name="recovery-kit-download"),

     # API
     path("service-accounts/", _admin.service_accounts_list,
          name="service-accounts-list"),
     path("service-accounts/new/", _admin.service_account_create,
          name="service-accounts-create"),
     path("service-accounts/<int:pk>/", _admin.service_account_detail,
          name="service-account-detail"),
     path("service-accounts/<int:pk>/revoke/", _admin.service_account_revoke,
          name="service-accounts-revoke"),
     path("service-accounts/<int:account_id>/tokens/issue/",
          _admin.service_token_issue, name="service-token-issue"),
     path("service-accounts/<int:account_id>/tokens/<uuid:token_id>/revoke/",
          _admin.service_token_revoke, name="service-token-revoke"),

     # IP access
    path("ip-rules/", _admin.ip_rules_page, name="ip-rules"),
]