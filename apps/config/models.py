from __future__ import annotations

from django.conf import settings
from django.core.validators import URLValidator
from django.db import models
from taggit.managers import TaggableManager

from apps.core.models import TimeStampedModel


class PlatformChoice(models.TextChoices):
    LINUX_DEBIAN = "linux.debian", "Debian"
    LINUX_UBUNTU = "linux.ubuntu", "Ubuntu"
    LINUX_ASTRA = "linux.astra", "Astra Linux"
    WINDOWS = "windows", "Windows"
    ANY = "any", "Любая"


class Repository(TimeStampedModel):
    """Репозиторий пакетов (apt/yum и др.)."""

    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    platform = models.CharField(
        max_length=32, choices=PlatformChoice.choices,
        default=PlatformChoice.LINUX_DEBIAN,
    )
    url = models.CharField(max_length=512, validators=[URLValidator(schemes=["http", "https", "file"])])
    components = models.CharField(max_length=256, blank=True,
                                  help_text='Например, "stable main contrib"')
    key_url = models.CharField(max_length=512, blank=True,
                               help_text="URL GPG-ключа репозитория")
    key_content = models.TextField(blank=True,
                                   help_text="GPG-ключ в base64 (если без URL)")
    priority = models.PositiveIntegerField(default=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Репозиторий"
        verbose_name_plural = "Репозитории"
        ordering = ["priority", "name"]

    def __str__(self) -> str:
        return self.name


class Certificate(TimeStampedModel):
    """Корневой сертификат для установки на целевые хосты."""

    name = models.CharField(max_length=128, unique=True,
                            help_text="Имя файла (например, internal-ca.crt)")
    description = models.TextField(blank=True)
    upload = models.FileField(upload_to="certificates/", blank=True)
    content_b64 = models.TextField(blank=True, editable=False,
                                   help_text="Заполняется автоматически из upload")
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Сертификат"
        verbose_name_plural = "Сертификаты"
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs):
        if self.upload:
            import base64
            try:
                self.upload.seek(0)
                self.content_b64 = base64.b64encode(self.upload.read()).decode()
            except Exception:
                pass
        super().save(*args, **kwargs)


class Package(TimeStampedModel):
    """Пакет для установки по прямой ссылке (.deb/.msi/.exe)."""

    name = models.CharField(max_length=128)
    description = models.TextField(blank=True)
    platform = models.CharField(
        max_length=32, choices=PlatformChoice.choices,
        default=PlatformChoice.LINUX_DEBIAN,
    )
    url = models.CharField(max_length=1024, validators=[URLValidator(schemes=["http", "https"])])
    sha256 = models.CharField(max_length=64, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Пакет"
        verbose_name_plural = "Пакеты"
        unique_together = [("name", "platform")]
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.platform})"


class ConfigProfile(TimeStampedModel):
    """Профиль конфигурации.

    Соответствует прежним config/profiles/*.json из postinstall.
    Может применяться к HostSet (общий набор) или к отдельному Host
    (точечно). Несколько профилей мержатся в порядке применения.
    """

    name = models.CharField(max_length=128)
    slug = models.SlugField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    platform = models.CharField(
        max_length=32, choices=PlatformChoice.choices,
        default=PlatformChoice.ANY,
    )
    is_active = models.BooleanField(default=True)

    # --- Композиция ---
    extra_ports = models.JSONField(
        default=list, blank=True,
        help_text="Дополнительные TCP/UDP порты (числа)",
    )
    jails = models.JSONField(
        default=list, blank=True,
        help_text="Jails fail2ban (имена)",
    )
    packages = models.JSONField(
        default=list, blank=True,
        help_text='Имена apt-пакетов, напр. ["nginx", "postgresql-15"]',
    )
    repositories = models.ManyToManyField(
        Repository, blank=True, related_name="profiles",
    )
    certificates = models.ManyToManyField(
        Certificate, blank=True, related_name="profiles",
    )
    package_installs = models.ManyToManyField(
        Package, blank=True, related_name="profiles",
    )

    postinstall_script = models.TextField(
        blank=True,
        help_text="Bash-скрипт, выполняется после модулей. "
                  "Плейсхолдеры: {allowed_ips}, {trusted_nets}",
    )

    settings = models.JSONField(
        default=dict, blank=True,
        help_text="Произвольный override в settings (deep merge)",
    )
    hardening = models.JSONField(
        default=dict, blank=True,
        help_text='{"mode": "apply", "checks": [...]}',
    )

    version = models.PositiveIntegerField(default=1)
    tags = TaggableManager(blank=True)

    class Meta:
        verbose_name = "Профиль"
        verbose_name_plural = "Профили"
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def to_snapshot(self) -> dict:
        """Полный снапшот профиля для ревизии."""
        return {
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "platform": self.platform,
            "is_active": self.is_active,
            "extra_ports": self.extra_ports,
            "jails": self.jails,
            "packages": self.packages,
            "repositories": [
                {"name": r.name, "url": r.url,
                 "components": r.components, "key_url": r.key_url}
                for r in self.repositories.all()
            ],
            "certificates": [
                {"name": c.name} for c in self.certificates.all()
            ],
            "package_installs": [
                {"name": p.name, "url": p.url, "sha256": p.sha256}
                for p in self.package_installs.all()
            ],
            "postinstall_script": self.postinstall_script,
            "settings": self.settings,
            "hardening": self.hardening,
            "version": self.version,
        }


class ConfigRevision(TimeStampedModel):
    """История версий профиля. Создаётся автоматически."""

    profile = models.ForeignKey(
        ConfigProfile, on_delete=models.CASCADE, related_name="revisions",
    )
    version = models.PositiveIntegerField()
    snapshot = models.JSONField()
    comment = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="config_revisions",
    )

    class Meta:
        verbose_name = "Ревизия профиля"
        verbose_name_plural = "Ревизии профилей"
        ordering = ["-version"]
        unique_together = [("profile", "version")]

    def __str__(self) -> str:
        return f"{self.profile.slug} v{self.version}"


class HostSetProfile(TimeStampedModel):
    """Связь HostSet ↔ ConfigProfile с порядком применения."""

    host_set = models.ForeignKey(
        "inventory.HostSet", on_delete=models.CASCADE,
        related_name="profile_links",
    )
    profile = models.ForeignKey(
        ConfigProfile, on_delete=models.PROTECT, related_name="host_set_links",
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Профиль набора"
        verbose_name_plural = "Профили наборов"
        unique_together = [("host_set", "profile")]
        ordering = ["order", "id"]


class HostExtraProfile(TimeStampedModel):
    """Профиль, применённый к конкретному хосту поверх набора."""

    host = models.ForeignKey(
        "inventory.Host", on_delete=models.CASCADE,
        related_name="extra_profile_links",
    )
    profile = models.ForeignKey(
        ConfigProfile, on_delete=models.PROTECT, related_name="host_links",
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Доп. профиль хоста"
        verbose_name_plural = "Доп. профили хостов"
        unique_together = [("host", "profile")]
        ordering = ["order", "id"]