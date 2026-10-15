from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.dashboard_view, name="index"),
    path("partial/metrics/", views.metrics_partial, name="metrics"),
    path("partial/recent/", views.recent_partial, name="recent"),
    path("partial/active/", views.active_partial, name="active"),
]