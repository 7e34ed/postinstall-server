from django.urls import path

from .views import HostDetailView, HostListView, host_detail_view

app_name = "inventory"

urlpatterns = [
    path("", HostListView.as_view(), name="host-list"),
    path("hosts/<int:pk>/", host_detail_view, name="host-detail"),
]