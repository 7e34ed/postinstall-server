import django_tables2 as tables

from .models import Host


class HostTable(tables.Table):
    selection = tables.TemplateColumn(
        template_code=(
            '<input type="checkbox" name="host_ids" '
            'value="{{ record.pk }}" class="checkbox checkbox-sm host-checkbox">'
        ),
        orderable=False,
        verbose_name="",
        attrs={"td": {"class": "w-8"}},
    )
    hostname = tables.Column(linkify=False, verbose_name="Hostname")
    domain = tables.Column(accessor="domain.name", verbose_name="Домен")
    host_set = tables.Column(accessor="host_set.name", verbose_name="Набор")
    drift = tables.TemplateColumn(
        template_name="inventory/_drift_badge.html",
        verbose_name="Дрифт", orderable=False,
    )
    managed = tables.BooleanColumn(verbose_name="Управляемый")
    agent_last_seen_at = tables.DateTimeColumn(
        format="Y-m-d H:i", verbose_name="Последний контакт",
    )
    actions = tables.TemplateColumn(
        template_name="inventory/_host_actions.html",
        orderable=False, verbose_name="",
        attrs={"td": {"class": "text-right whitespace-nowrap"}},
    )

    class Meta:
        model = Host
        fields = ("selection", "hostname", "domain", "host_set",
                  "ip_primary", "drift", "managed",
                  "agent_last_seen_at", "actions")
        attrs = {
            "class": "table table-zebra table-sm w-full",
            "thead": {"class": "bg-base-200"},
        }
        per_page = 50
        empty_text = "Хостов не найдено"

    def render_hostname(self, record):
        from django.urls import reverse
        from django.utils.html import format_html
        
        url = reverse("inventory:host-detail", args=[record.pk])
        return format_html(
            '<a href="{}" class="link font-medium">{}</a>',
            url, record.hostname,
        )