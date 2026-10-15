from django.urls import path

from . import views

app_name = "config"

urlpatterns = [
    path("profiles/", views.ProfileListView.as_view(), name="profile-list"),
    path("profiles/new/", views.profile_form_view, name="profile-create"),
    path("profiles/<slug:slug>/edit/", views.profile_form_view, name="profile-edit"),
    path("profiles/<slug:slug>/preview/", views.profile_preview_view, name="profile-preview"),
    path("profiles/<slug:slug>/delete/", views.profile_delete_view, name="profile-delete"),
]