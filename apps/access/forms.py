"""Формы для привязки и подтверждения клиентских сертификатов."""
from __future__ import annotations

import re

from django import forms
from django.core.exceptions import ValidationError

from .models import UserCertificate

FP_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class CertificateEnrollForm(forms.Form):
    """Пользователь вводит метаданные сертификата.

    Реальное значение fingerprint проверяется middleware при
    следующем запросе с mTLS. Здесь — только декларация.
    """

    label = forms.CharField(
        max_length=128,
        label="Метка",
        widget=forms.TextInput(attrs={
            "class": "input input-bordered w-full",
            "placeholder": "Rutoken #1, ноутбук, etc.",
        }),
    )

    fingerprint = forms.CharField(
        max_length=64, label="SHA-256 fingerprint",
        widget=forms.TextInput(attrs={
            "class": "input input-bordered w-full font-mono",
            "placeholder": "a1b2c3…",
            "autocomplete": "off",
        }),
    )

    subject_dn = forms.CharField(
        max_length=512, required=False,
        label="Subject DN",
        widget=forms.TextInput(attrs={
            "class": "input input-bordered w-full font-mono",
            "placeholder": "CN=ivan,OU=users,O=company",
        }),
    )

    valid_to = forms.DateTimeField(
        required=False,
        label="Действует до",
        widget=forms.DateTimeInput(attrs={
            "class": "input input-bordered w-full",
            "type": "datetime-local",
        }),
    )

    def clean_fingerprint(self):
        v = (self.cleaned_data.get("fingerprint") or "").strip().lower()
        v = v.replace(":", "").replace(" ", "")
        if not FP_RE.match(v):
            raise ValidationError(
                "Fingerprint должен быть SHA-256 hex (64 символа)."
            )
        return v

    def clean(self):
        cleaned = super().clean()
        fp = cleaned.get("fingerprint")
        if fp and UserCertificate.objects.filter(
            fingerprint_sha256=fp, is_active=True,
        ).exists():
            raise ValidationError(
                "Этот сертификат уже привязан к другому пользователю."
            )
        return cleaned