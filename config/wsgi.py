import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("DJANGO_CONFIGURATION", "Production")

from configurations.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()

# Попытка разблокировать секреты при старте. Не падаем, если не удалось —
# приложение поднимется в состоянии sealed и middleware отдаст 503.
from apps.secrets.runtime import runtime as _secrets_runtime  # noqa: E402

_secrets_runtime.try_auto_unlock()