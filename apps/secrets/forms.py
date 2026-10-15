"""Формы для UI секретов."""
from __future__ import annotations

import re

from django import forms
from django.core.exceptions import ValidationError

PATH_RE = re.compile(r"^[a-zA-Z0-9_.\-/]+$")
KEY_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")


def validate_path(path: str) -> None:
    if not path:
        raise ValidationError("Пустой path")
    if path.startswith("/") or path.endswith("/"):
        raise ValidationError("path не должен начинаться/заканчиваться на '/'")
    if "//" in path:
        raise ValidationError("path не должен содержать '//'")
    if ".." in path.split("/"):
        raise ValidationError("path не должен содержать '..'")
    if not PATH_RE.match(path):
        raise ValidationError(
            "path может содержать только a-z, A-Z, 0-9, '_', '.', '-', '/'"
        )
    if len(path) > 512:
        raise ValidationError("path слишком длинный (>512)")


def validate_key(key: str) -> None:
    if not key:
        raise ValidationError("Пустой key")
    if not KEY_RE.match(key):
        raise ValidationError(
            "key может содержать только a-z, A-Z, 0-9, '_', '.', '-'"
        )
    if len(key) > 128:
        raise ValidationError("key слишком длинный (>128)")


class SecretCreateForm(forms.Form):
    path = forms.CharField(
        max_length=512, label="Путь",
        widget=forms.TextInput(attrs={
            "class": "input input-bordered w-full font-mono",
            "placeholder": "credentials/example.local/admin",
        }),
        help_text="Уникальный путь в хранилище, например "
                  "credentials/example.local/admin",
    )
    key = forms.CharField(
        max_length=128, initial="value", label="Ключ",
        widget=forms.TextInput(attrs={
            "class": "input input-bordered w-full font-mono",
        }),
        help_text="Например: value, password, username, url",
    )
    value = forms.CharField(
        label="Значение",
        widget=forms.Textarea(attrs={
            "class": "textarea textarea-bordered w-full font-mono",
            "rows": 4, "autocomplete": "new-password",
        }),
    )

    def clean_path(self):
        v = self.cleaned_data["path"].strip()
        validate_path(v)
        return v

    def clean_key(self):
        v = self.cleaned_data["key"].strip() or "value"
        validate_key(v)
        return v


class SecretEditForm(forms.Form):
    """Редактирование существующей записи.

    Существующие ключи — по одному полю на каждый (пустое = не менять).
    Новые ключи — через пару полей new_key / new_value.
    """

    def __init__(self, *args, existing: dict[str, str] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.existing = existing or {}

        for k in sorted(self.existing.keys()):
            self.fields[f"v__{k}"] = forms.CharField(
                required=False, label=k,
                widget=forms.Textarea(attrs={
                    "class": "textarea textarea-bordered w-full font-mono",
                    "rows": 2, "placeholder": "•••••••• (не менять)",
                    "autocomplete": "new-password",
                }),
            )

        self.fields["new_key"] = forms.CharField(
            required=False, max_length=128, label="Новый ключ",
            widget=forms.TextInput(attrs={
                "class": "input input-bordered w-full font-mono",
                "placeholder": "например: extra_field",
            }),
        )
        self.fields["new_value"] = forms.CharField(
            required=False, label="Значение нового ключа",
            widget=forms.Textarea(attrs={
                "class": "textarea textarea-bordered w-full font-mono",
                "rows": 2,
            }),
        )

    def clean(self):
        cleaned = super().clean()
        nk = (cleaned.get("new_key") or "").strip()
        nv = cleaned.get("new_value") or ""
        if bool(nk) ^ bool(nv):
            raise ValidationError(
                "Для нового ключа нужны и «Новый ключ», и «Значение»"
            )
        if nk:
            validate_key(nk)
        return cleaned

    def updates(self) -> dict[str, str]:
        """Возвращает {key: value} для записи (без new_key)."""
        result: dict[str, str] = {}
        for k in self.existing:
            field = f"v__{k}"
            v = self.cleaned_data.get(field, "").strip()
            if v:
                result[k] = v
        return result

    def new_entry(self) -> tuple[str, str] | None:
        nk = (self.cleaned_data.get("new_key") or "").strip()
        nv = self.cleaned_data.get("new_value") or ""
        if nk and nv:
            return nk, nv
        return None