from django.urls import path

from . import views

app_name = "deploy"

urlpatterns = [
    path("", views.DeploymentListView.as_view(), name="list"),
    path("<uuid:pk>/", views.deployment_detail_view, name="detail"),
    path("<uuid:pk>/status/", views.deployment_status_view, name="status"),
    path("<uuid:pk>/cancel/", views.deployment_cancel_view, name="cancel"),
    path("<uuid:pk>/retry/", views.deployment_retry_view, name="retry"),

    # массовый деплой
    path("hosts/<int:host_id>/apply/", views.host_apply_view, name="host-apply"),
    path("bulk/apply/", views.bulk_apply_view, name="bulk-apply"),
    path("bulk/<uuid:pk>/", views.bulk_detail_view, name="bulk-detail"),
    path("bulk/<uuid:pk>/status/", views.bulk_status_partial, name="bulk-status"),
    path("bulk/<uuid:pk>/cancel/", views.bulk_cancel_view, name="bulk-cancel"),

    # дрифт
    path("drift/", views.drift_list_view, name="drift-list"),
    path("drift/rescan/<int:host_id>/", views.drift_rescan_view, name="drift-rescan"),
    path("drift/sync-all/", views.drift_sync_all_view, name="drift-sync-all"),
]