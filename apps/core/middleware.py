import time

from .models import AuditLog
from .utils import get_client_ip


class AuditMiddleware:
    SKIP_PREFIXES = ("/static/", "/media/", "/admin/", "/api/schema/",
                     "/api/docs/", "/favicon")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if any(request.path.startswith(p) for p in self.SKIP_PREFIXES):
            return self.get_response(request)

        started = time.monotonic()
        response = self.get_response(request)
        duration_ms = int((time.monotonic() - started) * 1000)

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                AuditLog.objects.create(
                    level=AuditLog.Level.INFO
                    if response.status_code < 400
                    else AuditLog.Level.WARNING,
                    logger="http",
                    message=f"{request.method} {request.path}",
                    user=request.user if request.user.is_authenticated else None,
                    ip=get_client_ip(request),
                    path=request.path,
                    method=request.method,
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                )
            except Exception:
                pass
        return response
