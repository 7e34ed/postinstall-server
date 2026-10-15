"""Настройки проекта через django-configurations.

Выбор конфигурации — переменная окружения DJANGO_CONFIGURATION:
    Development  — локальная разработка
    Production   — прод (k8s)
    Testing      — pytest
"""
from __future__ import annotations

import sys
from pathlib import Path

from configurations import Configuration, values
from loguru import logger

BASE_DIR = Path(__file__).resolve().parent.parent


class Base(Configuration):
    """Общие настройки для всех сред."""

    # site id
    SITE_ID = 1

    # --- Безопасность ---
    SECRET_KEY = values.SecretValue()
    DEBUG = values.BooleanValue(False)
    ALLOWED_HOSTS = values.ListValue(["localhost", "127.0.0.1"])
    CSRF_TRUSTED_ORIGINS = values.ListValue([])

    # --- Пути ---
    BASE_DIR = BASE_DIR

    # --- Приложения ---
    INSTALLED_APPS = [
        # django unfold admin, должна быть первой, перед django
        "unfold",
        "unfold.contrib.filters",
        "unfold.contrib.forms",

        # django
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "django.contrib.messages",
        "django.contrib.staticfiles",

        # --- allauth и его UI ---
        "allauth_ui",                 # <-- до allauth
        "allauth",
        "allauth.account",
        "allauth.mfa",

        "widget_tweaks",
        "slippers",

        # 3rd party
        "rest_framework",
        "drf_spectacular",
        "django_filters",
        "django_tables2",
        "guardian",
        "constance",
        "constance.backends.database",
        "django_vite",
        "simple_history",
        "taggit",
        "storages",

        # Наши приложения
        "apps.core",
        "apps.access",
        "apps.audit",
        "apps.inventory",
        "apps.config",
        "apps.deploy",
        "apps.dashboard",
        "apps.secrets",
        "apps.credentials",
        "apps.api",
        "apps.ldap_sync",
    ]

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "whitenoise.middleware.WhiteNoiseMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
        "simple_history.middleware.HistoryRequestMiddleware",

        # allauth
        "allauth.account.middleware.AccountMiddleware",

        "apps.access.mtls_middleware.MTLSAuthenticationMiddleware", 
        
        # кастом-миддлвари приложения
        # Access control: setup → role notice → sealed → audit
        "apps.access.middleware.SetupPhaseMiddleware",          # фаза установки, не пропускать до настройки дальше
        "apps.access.middleware.RoleChangeNoticeMiddleware",    
        "apps.access.middleware.IPAllowlistMiddleware",
        "apps.access.middleware.MfaEnforcementMiddleware",
        "apps.access.middleware.AalEnforcementMiddleware",      # Опеределить AAL
        "apps.secrets.middleware.SealedGateMiddleware",
        "apps.core.middleware.AuditMiddleware",
    ]

    ROOT_URLCONF = "config.urls"

    TEMPLATES = [
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [BASE_DIR / "templates"],
            "APP_DIRS": True,
            "OPTIONS": {
                "context_processors": [
                    "django.template.context_processors.request",
                    "django.contrib.auth.context_processors.auth",
                    "django.contrib.messages.context_processors.messages",
                    "apps.access.context_processors.access_flags",
                ],
            },
        },
    ]

    WSGI_APPLICATION = "config.wsgi.application"
    ASGI_APPLICATION = "config.asgi.application"

    # --- База ---
    DATABASES = values.DatabaseURLValue(
        "postgres://postinstall:postinstall@localhost:5432/postinstall",
    )
    DATABASES["default"]["CONN_MAX_AGE"] = 60
    DATABASES["default"]["ATOMIC_REQUESTS"] = False

    DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

    # --- Auth ---
    AUTH_PASSWORD_VALIDATORS = [
        {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
        {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
        {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
        {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    ]

    AUTHENTICATION_BACKENDS = [
        # Порядок важен: если RADIUS выключен или auth_source=local —
        # RadiusBackend возвращает None, и Django идёт дальше.
        "apps.access.auth_backends.RadiusBackend",
        "apps.access.auth_backends.LocalOnlyBackend",   # вместо "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
    ]

    ANONYMOUS_USER_NAME = None
    GUARDIAN_MONKEY_PATCH = True

    # --- i18n ---
    LANGUAGE_CODE = "ru-ru"
    TIME_ZONE = "Europe/Moscow"
    USE_I18N = True
    USE_TZ = True

    # --- Статика и медиа ---
    STATIC_URL = "/static/"
    STATIC_ROOT = BASE_DIR / "staticfiles"
    STATICFILES_DIRS = [BASE_DIR / "static"]
    MEDIA_URL = "/media/"
    MEDIA_ROOT = BASE_DIR / "media"

    STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }

    # --- DRF ---
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "rest_framework.authentication.SessionAuthentication",
            "apps.api.authentication.AgentSignatureAuthentication",
        ],
        "DEFAULT_PERMISSION_CLASSES": [
            "rest_framework.permissions.IsAuthenticated",
        ],
        "DEFAULT_FILTER_BACKENDS": [
            "django_filters.rest_framework.DjangoFilterBackend",
        ],
        "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
        "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
        "PAGE_SIZE": 50,
        "UNAUTHENTICATED_USER": None,
        "DEFAULT_THROTTLE_CLASSES": [
            "rest_framework.throttling.ScopedRateThrottle",
        ],
        "DEFAULT_THROTTLE_RATES": {
            "service_account": "600/hour",
            "agent": "3600/hour",
        },
    }

    SPECTACULAR_SETTINGS = {
        "TITLE": "postinstall-server API",
        "DESCRIPTION": "API for psi-agent and UI",
        "VERSION": "0.1.0",
        "SERVE_INCLUDE_SCHEMA": False,
    }

    # --- Constance ---
    CONSTANCE_BACKEND = "constance.backends.database.DatabaseBackend"
    CONSTANCE_DATABASE_CACHE_BACKEND = "default"
    CONSTANCE_CONFIG = {
        # Секреты и движок
        "SECRETS_BACKEND": ("local", "local | openbao | keepass"),
        "OPENBAO_URL": ("", "URL OpenBao"),
        "OPENBAO_TOKEN": ("", "Token OpenBao"),
        "KEEPASS_DB_PATH": ("", "Путь к .kdbx"),
        "KEEPASS_PASSWORD": ("", "Пароль .kdbx"),
        "SECRETS_RENEW_INTERVAL": (1800, "Интервал renew токена OpenBao (сек)"),
        "SECRETS_HEALTH_INTERVAL": (300, "Интервал health-check (сек)"),

        # Агент
        "AGENT_POLL_INTERVAL": (300, "Интервал poll агента (сек)"),
        "AGENT_HEARTBEAT_INTERVAL": (60, "Интервал heartbeat (сек)"),
        
        # MFA
        "MFA_ENABLED": (True, "Разрешить MFA (TOTP, recovery codes)"),
        "MFA_REQUIRED_FOR_SUPERVISOR": (True, "Обязать SUPERVISOR'ов включать MFA"),
        "MFA_REQUIRED_FOR_ADMIN": (True, "Обязать ADMIN'ов включать MFA"),
        "MFA_REQUIRED_FOR_OPERATOR": (False, "Обязать OPERATOR'ов включать MFA"),
        "MFA_REQUIRED_FOR_AUDITOR": (False, "Обязать AUDITOR'ов включать MFA"),
        "MFA_GRACE_PERIOD_HOURS": (24, "Время на настройку MFA (часов)"),

        # Аутентификация
        "AUTH_HIGH_SECURITY_MODE": (False,
            "Усиленный режим для SUPERVISOR/ADMIN (обязательный hardware)"),
        
        # --- Перенесено в constance ---
        "AUTH_AAL3_STRICT": (False,
            "Требовать hardware для AAL3 (отключено пока WebAuthn не развёрнут)"),
        "AUTH_AAL_UPGRADE_TTL": (900,
            "Время жизни AAL2/AAL3 сессии (сек)"),
        
        # MTLS (пользовательские сертификаты, включая hardware)
        "AUTH_MTLS_ENABLED": (False,
            "Включить аутентификацию через клиентские сертификаты"),
        "AUTH_MTLS_AUTO_LOGIN": (False,
            "Автоматический вход по одному сертификату (без пароля)"),
        "AUTH_MTLS_ALLOW_SELF_ENROLL": (True,
            "Разрешить пользователям привязывать свои сертификаты через UI"),

        # Radius backend settings for Aladdin
        "AUTH_RADIUS_ENABLED": (False,
            "Разрешить аутентификацию через RADIUS / Aladdin HOTP"),
        "AUTH_RADIUS_HOST": ("", "IP или hostname RADIUS-сервера"),
        "AUTH_RADIUS_PORT": (1812, "Порт RADIUS (обычно 1812)"),
        "AUTH_RADIUS_SECRET": ("", "Shared secret для RADIUS"),
        "AUTH_RADIUS_NAS_ID": ("postinstall-server",
            "NAS-Identifier, передаётся в RADIUS"),
        "AUTH_RADIUS_TIMEOUT": (3, "Timeout запроса к RADIUS (сек)"),
        "AUTH_RADIUS_RETRIES": (2, "Количество повторов при timeout"),
        "AUTH_RADIUS_FAIL_OPEN": (False,
            "При недоступности RADIUS разрешить локальную аутентификацию "
            "(НЕ РЕКОМЕНДУЕТСЯ, только для break-glass)"),
        "AUTH_RADIUS_TEST_USER": ("",
            "Логин для проверки соединения из UI (не обязателен)"),

        # break-glass & activity
        "ACCESS_BREAK_GLASS_AUTO_DISABLE_HOURS": (24,
            "Авто-выключение break-glass через N часов"),
        "ACCESS_REVIEW_INTERVAL_DAYS": (90,
            "Интервал access review (дней)"),
        "ACCESS_REVIEW_DUE_DAYS": (14,
            "Срок ответа на access review (дней)"),

        # rate limits access rules
        "RATELIMIT_LOGIN_PER_IP": (20,
            "Максимум логинов с одного IP за 15 минут"),
        "RATELIMIT_LOGIN_PER_USER": (10,
            "Максимум логинов на пользователя за 15 минут"),
        "RATELIMIT_SENSITIVE_ACTIONS": (30,
            "Максимум sensitive-действий в час"),
        "RATELIMIT_API_PER_TOKEN": (600,
            "Максимум API-запросов на токен в час"),
    }
    CONSTANCE_CONFIG_FIELDSETS = {
        "Секреты": (
            "SECRETS_BACKEND", "OPENBAO_URL", "OPENBAO_TOKEN",
            "KEEPASS_DB_PATH", "KEEPASS_PASSWORD",
        ),
        "Секреты — интервалы": (
            "SECRETS_RENEW_INTERVAL", "SECRETS_HEALTH_INTERVAL",
        ),
        "Агенты": ("AGENT_POLL_INTERVAL", "AGENT_HEARTBEAT_INTERVAL"),
        "MFA": (
            "MFA_ENABLED",
            "MFA_REQUIRED_FOR_SUPERVISOR",
            "MFA_REQUIRED_FOR_ADMIN",
            "MFA_REQUIRED_FOR_OPERATOR",
            "MFA_REQUIRED_FOR_AUDITOR",
            "MFA_GRACE_PERIOD_HOURS",
        ),
        "Безопасность (AAL)": (
            "AUTH_HIGH_SECURITY_MODE",
            "AUTH_AAL3_STRICT",
            "AUTH_AAL_UPGRADE_TTL",
        ),
        "Клиентские сертификаты (mTLS)": (
            "AUTH_MTLS_ENABLED",
            "AUTH_MTLS_AUTO_LOGIN",
            "AUTH_MTLS_ALLOW_SELF_ENROLL",
        ),
        "RADIUS / Aladdin HOTP": (
            "AUTH_RADIUS_ENABLED",
            "AUTH_RADIUS_HOST",
            "AUTH_RADIUS_PORT",
            "AUTH_RADIUS_SECRET",
            "AUTH_RADIUS_NAS_ID",
            "AUTH_RADIUS_TIMEOUT",
            "AUTH_RADIUS_RETRIES",
            "AUTH_RADIUS_TEST_USER",
            "AUTH_RADIUS_FAIL_OPEN",
        ),
        "Аварийный доступ и обзор": (
            "ACCESS_BREAK_GLASS_AUTO_DISABLE_HOURS",
            "ACCESS_REVIEW_INTERVAL_DAYS",
            "ACCESS_REVIEW_DUE_DAYS",
        ),
        "Rate limit": (
            "RATELIMIT_LOGIN_PER_IP",
            "RATELIMIT_LOGIN_PER_USER",
            "RATELIMIT_SENSITIVE_ACTIONS",
            "RATELIMIT_API_PER_TOKEN",
        ),
    }

    # --- Redis ---
    REDIS_URL = values.Value("redis://localhost:6379/0")
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": values.Value("redis://localhost:6379/0"),
        }
    }

    # --- Celery ---
    CELERY_BROKER_URL = values.Value("redis://localhost:6379/1")
    CELERY_RESULT_BACKEND = values.Value("redis://localhost:6379/1")
    CELERY_TASK_SERIALIZER = "json"
    CELERY_ACCEPT_CONTENT = ["json"]
    CELERY_TIMEZONE = "Europe/Moscow"
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 3600
    CELERY_TASK_SOFT_TIME_LIMIT = 3300

    # --- Vite ---
    DJANGO_VITE = {
        "default": {
            "dev_mode": False,
            "manifest_path": BASE_DIR / "static" / "dist" / ".vite" / "manifest.json",
            "dev_server_port": 5173,
            "dev_server_host": "127.0.0.1",
        }
    }

    # --- Статика в S3 (для Production) ---
    STATIC_STORAGE = values.Value("local")   # local | s3

    # --- Loguru ---
    PSI_LOG_LEVEL = values.Value("INFO")
    PSI_LOG_DIR = values.Value(str(BASE_DIR / "logs"))

    # --- Secrets ---
    # Мастер-ключ нигде не хранится на сервере. Ищем по цепочке:
    # FILE → FD → ENV → (опционально) TTY.
    SECRETS_MASTER_KEY_FILE = values.Value("")
    SECRETS_MASTER_KEY_FD = values.IntegerValue(0)
    SECRETS_MASTER_KEY = values.SecretValue("")
    SECRETS_ALLOW_INTERACTIVE = values.BooleanValue(False)

    # --- Argon2id ---
    SECRETS_ARGON2_TIME_COST = values.IntegerValue(3)
    SECRETS_ARGON2_MEMORY_COST = values.IntegerValue(65536)
    SECRETS_ARGON2_PARALLELISM = values.IntegerValue(4)

    # --- Transport guard для unseal ---
    # Требовать HTTPS+TLS>=SECRETS_MIN_TLS_VERSION для ввода мастер-ключа.
    SECRETS_REQUIRE_TLS_FOR_UNSEAL = values.BooleanValue(True)
    SECRETS_MIN_TLS_VERSION = values.Value("1.2")   # "1.2" | "1.3"
    # Разрешать unseal по HTTP — ТОЛЬКО для dev. В проде — false.
    SECRETS_ALLOW_INSECURE_UNSEAL = values.BooleanValue(False)
    # Заголовок от reverse proxy с версией TLS ($ssl_protocol в nginx).
    SECRETS_TLS_VERSION_HEADER = values.Value("HTTP_X_FORWARDED_TLS_VERSION")
    # CIDR доверенных proxy. Если REMOTE_ADDR в списке — доверяем X-Forwarded-*.
    # Если список пуст — заголовкам не доверяем вообще.
    SECRETS_TRUSTED_PROXIES = values.ListValue([])

    # --- Access ---
    ACCESS_INVITE_TTL_HOURS = values.IntegerValue(24)
    ACCESS_INVITE_TTL_HOURS_DUAL = values.IntegerValue(72)
    ACCESS_DUAL_APPROVAL_REQUIRED = values.BooleanValue(True)
    ACCESS_MIN_SUPERVISORS = values.IntegerValue(2)

    # --- Email ---
    EMAIL_BACKEND = values.Value(
        "django.core.mail.backends.console.EmailBackend"
    )
    EMAIL_HOST = values.Value("")
    EMAIL_PORT = values.IntegerValue(587)
    EMAIL_HOST_USER = values.Value("")
    EMAIL_HOST_PASSWORD = values.SecretValue("")
    EMAIL_USE_TLS = values.BooleanValue(True)
    EMAIL_USE_SSL = values.BooleanValue(False)
    DEFAULT_FROM_EMAIL = values.Value("noreply@postinstall.local")
    SITE_NAME = values.Value("postinstall-server")
    ACCESS_PUBLIC_BASE_URL = values.Value("")

    # --- allauth ---
    ACCOUNT_LOGIN_METHODS = {"username"}
    ACCOUNT_SIGNUP_FIELDS = ["username*", "password1*", "password2*"]
    ACCOUNT_ALLOW_REGISTRATION = False
    ACCOUNT_EMAIL_VERIFICATION = "none"
    ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = False
    ACCOUNT_LOGOUT_ON_GET = False
    ACCOUNT_LOGOUT_REDIRECT_URL = "/accounts/login/"
    ACCOUNT_SESSION_REMEMBER = False
    LOGIN_REDIRECT_URL = "/"
    LOGIN_URL = "/accounts/login/"
    LOGOUT_REDIRECT_URL = "/accounts/login/"
    ACCOUNT_ADAPTER = "apps.access.allauth.AccountAdapter"
    ACCOUNT_FORMS = {
        "login": "apps.access.allauth.StrictLoginForm",
    }

    # --- django-allauth-ui ---
    ALLAUTH_UI_THEME = values.Value("dark")

    # --- MFA (allauth.mfa) ---
    MFA_SUPPORTED_TYPES = ["totp", "recovery_codes"]
    MFA_TOTP_ISSUER = values.Value("postinstall-server")
    MFA_RECOVERY_CODE_COUNT = 10
    MFA_RECOVERY_CODE_DIGITS = 8

    # Аутентификация
    # --- mTLS ---
    # CIDR доверенных reverse proxy. Если пусто — заголовки X-SSL-Client-*
    # не принимаются вовсе.
    AUTH_TRUSTED_PROXIES = values.ListValue([])

    # Fallback: значения по умолчанию, если constance недоступен.
    # В реальной эксплуатации используются constance-настройки.
    AUTH_MTLS_ENABLED = values.BooleanValue(False)
    AUTH_MTLS_AUTO_LOGIN = values.BooleanValue(False)
    AUTH_MTLS_ALLOW_SELF_ENROLL = values.BooleanValue(True)

    # Рековери-кит
    ACCESS_RECOVERY_KIT_DIR = values.Value("/var/lib/postinstall/recovery")

    # --- Audit ---
    AUDIT_SYSLOG_ENABLED = values.BooleanValue(False)
    AUDIT_SYSLOG_HOST = values.Value("localhost")
    AUDIT_SYSLOG_PORT = values.IntegerValue(514)
    AUDIT_SYSLOG_FACILITY = values.Value("local0")
    AUDIT_FILE_PATH = values.Value("/var/log/postinstall/audit-export.jsonl")
    AUDIT_SEAL_INTERVAL_HOURS = values.IntegerValue(24)
    AUDIT_VERIFY_INTERVAL_HOURS = values.IntegerValue(6)
    AUDIT_VERIFY_MAX_RECORDS = values.IntegerValue(10000)

    # --- LDAP ---
    LDAP_DEFAULT_TIMEOUT = values.IntegerValue(5)
    LDAP_ENABLED = values.BooleanValue(False)

    @classmethod
    def post_setup(cls):
        """Настройка loguru после инициализации Configuration."""
        cls._setup_loguru()
        cls._setup_secrets_runtime()

    @classmethod
    def _setup_loguru(cls):
        from pathlib import Path as _Path
        log_dir = _Path(cls.PSI_LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        logger.remove()
        logger.add(
            sys.stderr,
            level=cls.PSI_LOG_LEVEL,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | "
                   "{name}:{line} | {message}",
        )
        logger.add(
            str(log_dir / "server.log"),
            level=cls.PSI_LOG_LEVEL,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
                   "{name}:{function}:{line} | {message}",
            rotation="50 MB",
            retention="30 days",
            encoding="utf-8",
            enqueue=True,
            backtrace=True,
            diagnose=False,
        )

    @classmethod
    def _setup_secrets_runtime(cls):
        from apps.secrets import blob as _blob
        from apps.secrets.runtime import runtime as _rt
        _rt.configure_argon2(_blob.Argon2Params(
            time_cost=cls.SECRETS_ARGON2_TIME_COST,
            memory_cost=cls.SECRETS_ARGON2_MEMORY_COST,
            parallelism=cls.SECRETS_ARGON2_PARALLELISM,
        ))


class Development(Base):
    """Локальная разработка."""

    DEBUG = True

    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

    STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }

    DJANGO_VITE = {
        "default": {
            "dev_mode": True,
            "manifest_path": BASE_DIR / "static" / "dist" / ".vite" / "manifest.json",
            "dev_server_port": 5173,
            "dev_server_host": "127.0.0.1",
        }
    }

    PSI_LOG_LEVEL = "DEBUG"

    # Email
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

    @classmethod
    def post_setup(cls):
        super().post_setup()
        # в dev разрешаем unseal по HTTP, но с громким warning в лог
        if not cls.SECRETS_ALLOW_INSECURE_UNSEAL:
            cls.SECRETS_ALLOW_INSECURE_UNSEAL = True
            from loguru import logger as _l

            _l.warning(
                "secrets: Development: SECRETS_ALLOW_INSECURE_UNSEAL=true "
                "(unseal over HTTP разрешён). "
                "В проде эта настройка должна быть false."
            )

        try:
            import debug_toolbar  # noqa: F401
            
            cls.INSTALLED_APPS.append("debug_toolbar")
            cls.MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")
            cls.INTERNAL_IPS = ["127.0.0.1"]
        except ImportError:
            pass


class Production(Base):
    """Продакшн (k8s)."""

    DEBUG = False

    # --- Безопасность ---
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_REFERRER_POLICY = "same-origin"
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
    CSRF_COOKIE_SAMESITE = "Lax"
    X_FRAME_OPTIONS = "DENY"

    # --- Статика в S3 ---
    STATIC_STORAGE = "s3"
    AWS_ACCESS_KEY_ID = values.Value("")
    AWS_SECRET_ACCESS_KEY = values.SecretValue("")
    AWS_STORAGE_BUCKET_NAME = values.Value("")
    AWS_S3_ENDPOINT_URL = values.Value("")
    AWS_S3_REGION_NAME = values.Value("")
    AWS_S3_CUSTOM_DOMAIN = values.Value("")
    AWS_S3_FILE_OVERWRITE = False
    AWS_QUERYSTRING_AUTH = False

    # Email
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

    @classmethod
    def post_setup(cls):
        super().post_setup()
        if cls.STATIC_STORAGE == "s3":
            cls._setup_s3()
        else:
            cls._setup_whitenoise()

    @classmethod
    def _setup_s3(cls):
        cls.STORAGES = {
            "default": {
                "BACKEND": "storages.backends.s3.S3Storage",
                "OPTIONS": {
                    "access_key": cls.AWS_ACCESS_KEY_ID,
                    "secret_key": cls.AWS_SECRET_ACCESS_KEY,
                    "bucket_name": cls.AWS_STORAGE_BUCKET_NAME,
                    "endpoint_url": cls.AWS_S3_ENDPOINT_URL,
                    "region_name": cls.AWS_S3_REGION_NAME,
                    "custom_domain": cls.AWS_S3_CUSTOM_DOMAIN or None,
                    "file_overwrite": False,
                    "querystring_auth": False,
                },
            },
            "staticfiles": {
                "BACKEND": "storages.backends.s3.S3Storage",
                "OPTIONS": {
                    "access_key": cls.AWS_ACCESS_KEY_ID,
                    "secret_key": cls.AWS_SECRET_ACCESS_KEY,
                    "bucket_name": cls.AWS_STORAGE_BUCKET_NAME,
                    "endpoint_url": cls.AWS_S3_ENDPOINT_URL,
                    "region_name": cls.AWS_S3_REGION_NAME,
                    "custom_domain": cls.AWS_S3_CUSTOM_DOMAIN or None,
                    "file_overwrite": True,        # для статики — да
                    "querystring_auth": False,
                    "location": "static",
                },
            },
        }
        if cls.AWS_S3_CUSTOM_DOMAIN:
            cls.STATIC_URL = f"https://{cls.AWS_S3_CUSTOM_DOMAIN}/static/"
        else:
            cls.STATIC_URL = f"{cls.AWS_S3_ENDPOINT_URL}/{cls.AWS_STORAGE_BUCKET_NAME}/static/"

    @classmethod
    def _setup_whitenoise(cls):
        cls.STORAGES = {
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {
                "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
            },
        }


class Testing(Base):
    """Для pytest."""

    DEBUG = False
    SECRET_KEY = "testing-key-not-secret"

    DATABASES = values.DatabaseURLValue(
        "postgres://postinstall:postinstall@localhost:5432/postinstall_test",
    )

    PSI_LOG_LEVEL = "WARNING"

    @classmethod
    def pre_setup(cls):
        super().pre_setup()
        logger.remove()
        logger.add(sys.stderr, level="WARNING")