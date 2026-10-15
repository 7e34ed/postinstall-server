from __future__ import annotations

import json

from django import forms
from django.core.exceptions import ValidationError
from django.utils.text import slugify

from .models import Certificate, ConfigProfile, Package, Repository


class StringListField(forms.CharField):
    """Список строк: значения через запятую или с новой строки."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("required", False)
        kwargs.setdefault("widget", forms.Textarea(attrs={
            "rows": 4,
            "class": "textarea textarea-bordered w-full font-mono text-sm",
            "spellcheck": "false",
        }))
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        if isinstance(value, list):
            return "\n".join(str(v) for v in value)
        return super().prepare_value(value)

    def clean(self, value):
        value = super().clean(value)
        if not value:
            return []
        items: list[str] = []
        for chunk in value.replace(",", "\n").splitlines():
            chunk = chunk.strip()
            if chunk:
                items.append(chunk)
        # сохраняем порядок первого появления, убираем дубли
        seen: set[str] = set()
        out: list[str] = []
        for x in items:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out


class PortListField(StringListField):
    """Список портов: значения через запятую/строку, каждое в диапазоне 1..65535."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("label", "Дополнительные порты")
        kwargs.setdefault("help_text", "По одному в строке или через запятую")
        super().__init__(*args, **kwargs)

    def clean(self, value):
        items = super().clean(value)
        ports: list[int] = []
        for item in items:
            try:
                v = int(item)
            except (TypeError, ValueError):
                raise ValidationError(f"{item!r} — не число")
            if not 1 <= v <= 65535:
                raise ValidationError(f"Порт {v} вне диапазона 1–65535")
            ports.append(v)
        return sorted(set(ports))


class JSONFormField(forms.CharField):
    """JSON с валидацией. Пусто → {}."""

    def __init__(self, *args, empty_value=None, **kwargs):
        kwargs.setdefault("required", False)
        kwargs.setdefault("widget", forms.Textarea(attrs={
            "rows": 14,
            "class": "textarea textarea-bordered w-full font-mono text-xs",
            "spellcheck": "false",
        }))
        super().__init__(*args, **kwargs)
        self.empty_value = empty_value if empty_value is not None else {}

    def prepare_value(self, value):
        if value in (None, "", {}):
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, ensure_ascii=False)
        return str(value)

    def clean(self, value):
        value = super().clean(value)
        if not value or not value.strip():
            return self.empty_value
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Неверный JSON: {exc}") from exc


class ConfigProfileForm(forms.ModelForm):
    slug = forms.SlugField(
        required=False,
        label="Slug",
        help_text="Латиница/цифры/дефис; если пусто — сгенерируется из названия",
        widget=forms.TextInput(attrs={"class": "input input-bordered w-full"}),
    )

    extra_ports = PortListField()
    jails = StringListField(
        label="Jails fail2ban",
        help_text="Имена фильтров, например: sshd, nginx",
    )
    packages = StringListField(
        label="Пакеты (apt)",
        help_text="Имена пакетов, например: nginx, postgresql-15",
    )
    postinstall_script = forms.CharField(
        required=False,
        label="postinstall_script",
        help_text="Bash. Плейсхолдеры {allowed_ips} / {trusted_nets} подставляются",
        widget=forms.Textarea(attrs={
            "rows": 12,
            "class": "textarea textarea-bordered w-full font-mono text-xs",
            "spellcheck": "false",
            "placeholder": "systemctl enable nginx\nsystemctl start nginx",
        }),
    )
    settings = JSONFormField(label="Settings override (JSON)")
    hardening = JSONFormField(label="Hardening (JSON)")

    repositories = forms.ModelMultipleChoiceField(
        queryset=Repository.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    certificates = forms.ModelMultipleChoiceField(
        queryset=Certificate.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    package_installs = forms.ModelMultipleChoiceField(
        queryset=Package.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = ConfigProfile
        fields = [
            "name", "slug", "description", "platform", "is_active", "tags",
            "extra_ports", "jails", "packages",
            "repositories", "certificates", "package_installs",
            "postinstall_script", "settings", "hardening",
        ]
        widgets = {
            "name": forms.TextInput(attrs={"class": "input input-bordered w-full"}),
            "description": forms.Textarea(attrs={
                "rows": 3,
                "class": "textarea textarea-bordered w-full",
            }),
            "platform": forms.Select(attrs={"class": "select select-bordered w-full"}),
            "tags": forms.TextInput(attrs={"class": "input input-bordered w-full"}),
        }

    def clean_slug(self):
        slug = (self.cleaned_data.get("slug") or "").strip()
        if not slug:
            slug = slugify(self.cleaned_data.get("name") or "")
        return slug

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("slug"):
            self.add_error("slug", "Не удалось сгенерировать slug — задайте вручную")
        return cleaned

    # --- виджеты для чекбоксов M2M через шаблон ---

    def _style_checkbox_field(self, name: str):
        field = self.fields[name]
        field.widget.attrs.update({"class": "checkbox checkbox-sm"})