from django.urls import path

from . import views

app_name = "credentials"

urlpatterns = [
    path("", views.CredentialListView.as_view(), name="list"),
    path("new/", views.credential_form_view, name="create"),
    path("<int:pk>/edit/", views.credential_form_view, name="edit"),
    path("<int:pk>/delete/", views.credential_delete_view, name="delete"),
]