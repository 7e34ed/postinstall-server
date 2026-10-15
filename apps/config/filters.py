import django_filters as df
from django.db.models import Q

from .models import ConfigProfile


class ProfileFilter(df.FilterSet):
    q = df.CharFilter(method="filter_q", label="Поиск")
    platform = df.ChoiceFilter(choices=ConfigProfile._meta.get_field("platform").choices)
    is_active = df.BooleanFilter()

    class Meta:
        model = ConfigProfile
        fields = ["platform", "is_active"]

    def filter_q(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(Q(name__icontains=value) | Q(slug__icontains=value))