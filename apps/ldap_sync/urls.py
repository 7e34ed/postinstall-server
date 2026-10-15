from django.urls import path

from . import views

app_name = "ldap"

urlpatterns = [
    path("", views.ldap_dashboard, name="ldap-dashboard"),
]