from django.http import JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def health(request):
    """Health-check с состоянием secrets runtime.
    
    Коды (по README):
      uninitialized → 200 (ServerKey нет, ещё не setup)
      sealed        → 503 (ServerKey есть, ключ не в памяти)
      unsealed      → 200 (всё работает)
    """
    from apps.secrets.runtime import runtime

    status = runtime.status()
    state = status.state  # "uninitialized" | "sealed" | "unsealed"

    payload = {
        "status": "ok" if state != "sealed" else "sealed",
        "version": "0.1.0",
        "secrets": {
            "state": state,
        },
    }

    http_status = 503 if state == "sealed" else 200
    return JsonResponse(payload, status=http_status)