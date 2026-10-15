from django import forms
from django.contrib import admin
from unfold.admin import ModelAdmin

from .models import Credential


class CredentialAdminForm(forms.ModelForm):
    password_value = forms.CharField(
        required=False, widget=forms.PasswordInput(render_value=False),
        label="Пароль",
        help_text="Оставьте пустым, чтобы не менять",
    )
    ssh_key_value = forms.CharField(
        required=False, widget=forms.Textarea(attrs={"rows": 12, "class": "vLargeTextField"}),
        label="Приватный SSH-ключ",
        help_text="Оставьте пустым, чтобы не менять",
    )
    passphrase_value = forms.CharField(
        required=False, widget=forms.PasswordInput(render_value=False),
        label="Passphrase SSH-ключа",
    )

    class Meta:
        model = Credential
        fields = [
            "name", "kind", "description", "username",
            "domain", "host_set", "host",
            "is_active", "tags",
        ]

    def save(self, commit=True):
        cred = super().save(commit=False)

        from .services import create_credential, get_credential_value

        if not cred.pk:
            # при создании — используем create_credential
            if commit:
                cred = create_credential(
                    name=cred.name, kind=cred.kind,
                    username=cred.username, description=cred.description,
                    domain=cred.domain, host_set=cred.host_set,
                    host=cred.host,
                    password=self.cleaned_data.get("password_value"),
                    ssh_key=self.cleaned_data.get("ssh_key_value"),
                    passphrase=self.cleaned_data.get("passphrase_value"),
                )
            return cred

        if commit:
            cred.save()

        # обновляем значения секретов, если они введены
        from apps.secrets.models import SecretRef
        from apps.secrets.services import set_secret

        def _upsert(path: str, value: str, field_name: str):
            set_secret(path, "value", value,
                       display_name=f"Credential: {cred.name} ({field_name})")
            ref = SecretRef.objects.filter(backend="local", path=path).first()
            return ref

        pwd = self.cleaned_data.get("password_value")
        if pwd:
            cred.secret_password = _upsert(cred.secret_path_password, pwd, "password")
        key = self.cleaned_data.get("ssh_key_value")
        if key:
            cred.secret_ssh_key = _upsert(cred.secret_path_ssh_key, key, "ssh_key")
        pp = self.cleaned_data.get("passphrase_value")
        if pp:
            cred.secret_passphrase = _upsert(cred.secret_path_passphrase, pp, "passphrase")
        if pwd or key or pp:
            cred.save()

        return cred


@admin.register(Credential)
class CredentialAdmin(ModelAdmin):
    form = CredentialAdminForm
    list_display = ("name", "kind", "username", "domain", "host_set", "host",
                    "is_active", "updated_at")
    list_filter = ("kind", "is_active", "domain")
    search_fields = ("name", "username", "description")
    autocomplete_fields = ("domain", "host_set", "host")
    readonly_fields = ("secret_password", "secret_ssh_key", "secret_passphrase",
                       "created_at", "updated_at")
    fieldsets = (
        ("Основное", {
            "fields": ("name", "kind", "description", "username", "is_active", "tags"),
        }),
        ("Область", {
            "fields": ("domain", "host_set", "host"),
            "description": "Заполните хотя бы одно. Чем специфичнее — тем приоритетнее.",
        }),
        ("Значения секретов", {
            "fields": ("password_value", "ssh_key_value", "passphrase_value"),
            "description": "Оставьте пустыми, чтобы не менять. "
                           "Значения хранятся в secrets-модуле.",
        }),
        ("Связи с секретами (read-only)", {
            "fields": ("secret_password", "secret_ssh_key", "secret_passphrase"),
            "classes": ("collapse",),
        }),
    )