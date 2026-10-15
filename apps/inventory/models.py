from django.db import models
from taggit.managers import TaggableManager

from apps.core.models import TimeStampedModel


class Domain(TimeStampedModel):
    """Тенант. Домен = организация."""

    name = models.CharField(max_length=253, unique=True, verbose_name="Домен")
    description = models.TextField(blank=True, verbose_name="Описание")

    ldap_url = models.CharField(max_length=512, blank=True, verbose_name="LDAP URL")
    ldap_base_dn = models.CharField(max_length=512, blank=True, verbose_name="Base DN")
    ldap_bind_dn = models.CharField(max_length=512, blank=True, verbose_name="Bind DN")
    ldap_sync_enabled = models.BooleanField(default=False, verbose_name="LDAP-синк")
    ldap_last_sync_at = models.DateTimeField(null=True, blank=True,
                                             verbose_name="Последний синк")
    ldap_last_sync_status = models.CharField(max_length=64, blank=True,
                                             verbose_name="Статус синка")
    # Не нужно, используется модель credentials
    # domain_join_secret = models.ForeignKey(
    #     "secrets.SecretRef", null=True, blank=True,
    #     on_delete=models.SET_NULL,
    #     related_name="+",
    #     help_text="Секрет с паролем домена (path: domains/<name>/domain_password, key: value)",
    # )
    class Meta:
        verbose_name = "Домен"
        verbose_name_plural = "Домены"
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class HostSet(TimeStampedModel):
    class Platform(models.TextChoices):
        DEBIAN = "linux.debian", "Debian"
        UBUNTU = "linux.ubuntu", "Ubuntu"
        ASTRA = "linux.astra", "Astra Linux"
        WINDOWS = "windows", "Windows"

    domain = models.ForeignKey(
        Domain, on_delete=models.CASCADE, related_name="sets",
        verbose_name="Домен",
    )
    name = models.SlugField(max_length=64, verbose_name="Имя набора")
    description = models.TextField(blank=True, verbose_name="Описание")
    platform = models.CharField(
        max_length=32, choices=Platform.choices, default=Platform.DEBIAN,
        verbose_name="Платформа",
    )
    common_config = models.JSONField(
        default=dict, blank=True, verbose_name="Общие настройки",
    )
    common_hardening = models.JSONField(
        default=dict, blank=True, verbose_name="Общий hardening",
    )
    tags = TaggableManager(blank=True, verbose_name="Теги")
    profiles = models.ManyToManyField(
        "config.ConfigProfile",
        through="config.HostSetProfile",
        related_name="+",
        blank=True,
    )

    class Meta:
        unique_together = [("domain", "name")]
        verbose_name = "Набор хостов"
        verbose_name_plural = "Наборы хостов"
        ordering = ["domain", "name"]

    def __str__(self) -> str:
        return f"{self.domain.name}/{self.name}"

    def resolved_settings(self) -> dict:
        """common_config + overrides (deep merge)."""
        from apps.core.utils import deep_merge

        result = deep_merge(
            self.host_set.common_config or {},
            self.overrides or {},
        )
        result.setdefault("host", {})["hostname"] = self.hostname
        return result

class Host(TimeStampedModel):
    class Source(models.TextChoices):
        MANUAL = "manual", "Вручную"
        LDAP = "ldap", "LDAP"
        API = "api", "API"

    domain = models.ForeignKey(
        Domain, on_delete=models.CASCADE, related_name="hosts",
        verbose_name="Домен",
    )
    host_set = models.ForeignKey(
        HostSet, on_delete=models.PROTECT, related_name="hosts",
        verbose_name="Набор",
    )

    hostname = models.CharField(max_length=253, verbose_name="Hostname")
    fqdn = models.CharField(max_length=253, blank=True, verbose_name="FQDN")
    ip_primary = models.GenericIPAddressField(null=True, blank=True,
                                              verbose_name="IP")
    os_family = models.CharField(max_length=32, blank=True, verbose_name="ОС")

    managed = models.BooleanField(default=False, verbose_name="Управляемый")
    overrides = models.JSONField(default=dict, blank=True,
                                 verbose_name="Переопределения")
    hardening_overrides = models.JSONField(default=dict, blank=True,
                                           verbose_name="Переопределения hardening")

    source = models.CharField(
        max_length=16, choices=Source.choices, default=Source.MANUAL,
        verbose_name="Источник",
    )

    agent_registered_at = models.DateTimeField(null=True, blank=True,
                                               verbose_name="Агент зарегистрирован")
    agent_version = models.CharField(max_length=32, blank=True,
                                     verbose_name="Версия агента")
    agent_last_seen_at = models.DateTimeField(null=True, blank=True,
                                              verbose_name="Последний контакт")
    extra_profiles = models.ManyToManyField(
            "config.ConfigProfile",
            through="config.HostExtraProfile",
            related_name="+",
            blank=True,
        )
    # --- Drift ---
    last_deployed_config_hash = models.CharField(
        max_length=64, blank=True,
        verbose_name="Hash последнего деплоя",
    )
    last_deployed_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name="Последний успешный деплой",
    )
    drift_checked_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name="Последняя проверка дрифта",
    )
    drift_detected_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name="Дрифт обнаружен",
    )
    
    class Meta:
        unique_together = [("domain", "hostname")]
        verbose_name = "Хост"
        verbose_name_plural = "Хосты"
        ordering = ["domain", "hostname"]
        indexes = [
            models.Index(fields=["domain", "hostname"]),
            models.Index(fields=["-agent_last_seen_at"]),
        ]
        permissions = [
            ("deploy_host", "Can deploy to host"),
            ("view_deployments", "Can view host deployments"),
        ]

    def __str__(self) -> str:
        return self.fqdn or f"{self.hostname}.{self.domain.name}"


    def resolved_settings(self) -> dict:
        from apps.config.services import resolve_for_host
        return resolve_for_host(self)

    def resolved_hardening(self) -> dict:
        from apps.config.services import resolve_hardening_for_host
        return resolve_hardening_for_host(self)