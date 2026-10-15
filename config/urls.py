from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    # allauth (login, logout, 2fa)
    path("accounts/", include("allauth.urls")),

    # Django admin login → редирект на allauth login (единый вход с MFA)
    path("admin/login/", RedirectView.as_view(
        url="/accounts/login/", query_string=True, permanent=False,
    )),

    # admin
    path("admin/secrets/", include("apps.secrets.urls")),
    path("admin/", admin.site.urls),

    # access
    path("access/", include("apps.access.urls")),
    
    # api
    path("api/v1/", include("apps.api.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger"),

    # assets
    path("hosts/", include("apps.inventory.urls")),
    path("config/", include("apps.config.urls")),
    path("deploy/", include("apps.deploy.urls")),
    path("credentials/", include("apps.credentials.urls")),

    # dashboard
    path("", include("apps.dashboard.urls")),
]