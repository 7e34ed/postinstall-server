import django_filters as df
from django.db.models import Q

from apps.inventory.models import Domain, Host

from .models import Deployment


class DeploymentFilter(df.FilterSet):
    q = df.CharFilter(method="filter_q", label="Поиск")
    domain = df.ModelChoiceFilter(
        queryset=Domain.objects.all(), label="Домен",
        field_name="host__domain",
    )
    host = df.ModelChoiceFilter(
        queryset=Host.objects.all(), label="Хост",
        field_name="host",
    )
    status = df.ChoiceFilter(choices=Deployment.Status.choices)

    class Meta:
        model = Deployment
        fields = ["domain", "host", "status"]

    def filter_q(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(id__icontains=value)
            | Q(host__hostname__icontains=value)
            | Q(host__fqdn__icontains=value)
        )