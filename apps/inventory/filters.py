import django_filters as df
from django.db.models import Q

from .models import Domain, Host, HostSet


class HostFilter(df.FilterSet):
    q = df.CharFilter(method="filter_q", label="Поиск")
    domain = df.ModelChoiceFilter(queryset=Domain.objects.all(), label="Домен")
    host_set = df.ModelChoiceFilter(queryset=HostSet.objects.all(), label="Набор")
    managed = df.BooleanFilter(label="Управляемый")

    class Meta:
        model = Host
        fields = ["domain", "host_set", "managed", "source"]

    def filter_q(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(hostname__icontains=value)
            | Q(fqdn__icontains=value)
            | Q(ip_primary__icontains=value)
        )