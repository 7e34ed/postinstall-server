from __future__ import annotations

from django.http import HttpResponse
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.urls import reverse

from .runtime import runtime

EXEMPT_PREFIXES = (
    "/static/",
    "/media/",
    "/favicon",
    "/admin/login/",
    "/admin/logout/",
    "/admin/secrets/unlock/",
    "/admin/secrets/init/",
    "/api/v1/health",
    "/api/schema/",
    "/api/docs/",
)


class SealedGateMiddleware:
    """Если secrets не разблокированы и запись ServerKey существует —
    отдаём 503 для всех, кроме белого списка.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self._is_exempt(request.path):
            return self.get_response(request)

        status = runtime.status()
        if status.state == "unsealed":
            return self.get_response(request)

        # uninitialized: пропускаем, но UI подскажет что делать
        if status.state == "uninitialized":
            if request.path.startswith("/admin/"):
                return self._response(request, status, initial=True)
            return self.get_response(request)

        # sealed
        return self._response(request, status, initial=False)

    @staticmethod
    def _is_exempt(path: str) -> bool:
        return any(path.startswith(p) for p in EXEMPT_PREFIXES)

    def _response(self, request, status, *, initial: bool):
        html = render_to_string("secrets/sealed.html", {
            "state": status.state,
            "initial": initial,
            "unlock_url": reverse("secrets:unlock"),
        }, request=request)
        return HttpResponse(html, status=503, content_type="text/html")