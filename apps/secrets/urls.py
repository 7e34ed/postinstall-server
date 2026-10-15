from django.urls import path

from . import admin_views, views

app_name = "secrets"

urlpatterns = [
    path("unlock/", views.unlock_view, name="unlock"),
    path("backend/", admin_views.backend_page, name="backend"),
    path("backend/set/", admin_views.backend_set, name="backend-set"),
    path("backend/credentials/save/",
         admin_views.backend_credentials_save,
         name="backend-credentials-save"),
    path("backend/credentials/clear/",
         admin_views.backend_credentials_clear,
         name="backend-credentials-clear"),
    path("backend/test/", admin_views.backend_test, name="backend-test"),
    path("backend/renew/", admin_views.renew_openbao_now, name="renew-now"),
    path("migrations/", admin_views.migrations_page, name="migrations"),

    # --- прикладные секреты ---
    path("items/", admin_views.items_list, name="items"),
    path("items/new/", admin_views.item_new, name="item-new"),
    path("items/<path:path>/", admin_views.item_edit, name="item-edit"),
    path("items/<path:path>/delete/",
         admin_views.item_delete, name="item-delete"),
    path("items/<path:path>/keys/<str:key>/delete/",
         admin_views.item_key_delete, name="item-key-delete"),

    path("items/<path:path>/grant/", admin_views.grant_create,
         name="grant-create"),
    path("items/<path:path>/grant/<int:grant_id>/revoke/",
         admin_views.grant_revoke, name="grant-revoke"),
    path("items/<path:path>/transfer/", admin_views.transfer_initiate,
         name="transfer-initiate"),
    path("transfers/<uuid:transfer_id>/approve/",
         admin_views.transfer_approve, name="transfer-approve"),
]