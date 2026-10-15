from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models
from taggit.managers import TaggableManager

from apps.core.models import TimeStampedModel


class Credential(TimeStampedModel):
    """Учётные данные для доступа к хостам или домену.

    Одна запись = один логический "аккаунт для чего-то". Может быть:
      * доменной учёткой (для ввода хоста в домен, sudo, ssh);
      * локальной учёткой на наборе/хосте;
      * SSH-ключом.

    Область применения задаётся тремя FK: domain, host_set, host.
    Хотя бы один должен быть заполнен. Если заполнено несколько —
    credential применим к конкретному host или host_set, но
    "закреплён" за доменом как родителем.

    Правило резолва (см. services.resolve_credential):
      1) host        — самый специфичный
      2) host_set    — на уровне набора
      3) domain      — на уровне домена
    Берётся первая подходящая по (kind, scope) активная запись.
    """

    class Kind(models.TextChoices):
        DOMAIN_PASSWORD = "domain_password", "Доменная учётка (пароль)"
        DOMAIN_SSH_KEY = "domain_ssh_key", "Доменная учётка (SSH-ключ)"
        LOCAL_PASSWORD = "local_password", "Локальная учётка (пароль)"
        LOCAL_SSH_KEY = "local_ssh_key", "Локальная учётка (SSH-ключ)"
        SSH_KEY = "ssh_key", "SSH-ключ (без домена)"
        BOOTSTRAP_TOKEN = "bootstrap_token", "Bootstrap-токен"

    name = models.CharField(
        max_length=128, unique=True,
        help_text="Уникальное имя, например 'example.local-admin'",
    )
    kind = models.CharField(max_length=32, choices=Kind.choices, db_index=True)
    description = models.TextField(blank=True)

    # --- Область ---
    domain = models.ForeignKey(
        "inventory.Domain", null=True, blank=True,
        on_delete=models.CASCADE, related_name="credentials",
    )
    host_set = models.ForeignKey(
        "inventory.HostSet", null=True, blank=True,
        on_delete=models.CASCADE, related_name="credentials",
    )
    host = models.ForeignKey(
        "inventory.Host", null=True, blank=True,
        on_delete=models.CASCADE, related_name="credentials",
    )

    username = models.CharField(max_length=128, blank=True)

    # --- Секреты ---
    # Пароль / passphrase / private key хранятся в secrets-модуле.
    # Мы ссылаемся на SecretRef, а не храним значение здесь.
    secret_password = models.ForeignKey(
        "secrets.SecretRef", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
        help_text="Пароль (для password-kind)",
    )
    secret_ssh_key = models.ForeignKey(
        "secrets.SecretRef", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
        help_text="Приватный SSH-ключ (для ssh_key-kind)",
    )
    secret_passphrase = models.ForeignKey(
        "secrets.SecretRef", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
        help_text="Парольная фраза для SSH-ключа (опционально)",
    )

    is_active = models.BooleanField(default=True)
    tags = TaggableManager(blank=True)

    class Meta:
        verbose_name = "Учётные данные"
        verbose_name_plural = "Учётные данные"
        ordering = ["name"]
        indexes = [
            models.Index(fields=["kind", "is_active"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} [{self.get_kind_display()}]"

    def clean(self) -> None:
        if not (self.domain or self.host_set or self.host):
            raise ValidationError(
                "Учётные данные должны быть привязаны хотя бы к одному "
                "из: domain, host_set, host"
            )

        # Согласованность scope
        if self.host_set and self.host and self.host.host_set_id != self.host_set_id:
            raise ValidationError("host не принадлежит указанному host_set")
        if self.host and self.domain and self.host.domain_id != self.domain_id:
            raise ValidationError("host не принадлежит указанному domain")

        # Согласованность kind ↔ secret
        password_kinds = {
            self.Kind.DOMAIN_PASSWORD, self.Kind.LOCAL_PASSWORD,
            self.Kind.BOOTSTRAP_TOKEN,
        }
        ssh_kinds = {
            self.Kind.DOMAIN_SSH_KEY, self.Kind.LOCAL_SSH_KEY, self.Kind.SSH_KEY,
        }
        if self.kind in password_kinds and not self.secret_password:
            raise ValidationError(
                f"Для kind={self.kind} нужен secret_password"
            )
        if self.kind in ssh_kinds and not self.secret_ssh_key:
            raise ValidationError(
                f"Для kind={self.kind} нужен secret_ssh_key"
            )

    @property
    def secret_path_password(self) -> str:
        """Логический путь пароля в secrets-бэкенде.

        Используется при создании SecretRef.
        """
        return f"credentials/{self.name}/password"

    @property
    def secret_path_ssh_key(self) -> str:
        return f"credentials/{self.name}/ssh_key"

    @property
    def secret_path_passphrase(self) -> str:
        return f"credentials/{self.name}/passphrase"