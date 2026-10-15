"""Фильтры для списка учётных данных."""
from __future__ import annotations

import django_filters as df
from django.db.models import Q

from apps.inventory.models import Domain, Host, HostSet

from .models import Credential


class CredentialFilter(df.FilterSet):
    q = df.CharFilter(method="filter_q", label="Поиск")

    kind = df.ChoiceFilter(choices=Credential.Kind.choices, label="Тип")
    domain = df.ModelChoiceFilter(queryset=Domain.objects.all(), label="Домен")
    host_set = df.ModelChoiceFilter(queryset=HostSet.objects.all(), label="Набор")
    host = df.ModelChoiceFilter(queryset=Host.objects.all(), label="Хост")
    is_active = df.BooleanFilter(label="Активен")

    class Meta:
        model = Credential
        fields = ["kind", "domain", "host_set", "host", "is_active"]

    def filter_q(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(username__icontains=value)
            | Q(description__icontains=value)
        )