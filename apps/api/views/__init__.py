from django.http import JsonResponse
from django.views.decorators.http import require_GET


# TODO: Версия из global приложения
@require_GET
def health(request):
    return JsonResponse({"status": "ok", "version": "0.1.0"})
