import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html

from .models import Credential


class CredentialTable(tables.Table):
    name = tables.Column(linkify=False, verbose_name="Имя")
    kind = tables.Column(verbose_name="Тип")
    username = tables.Column(verbose_name="Пользователь")
    scope = tables.TemplateColumn(
        template_code=(
            "{% if record.host %}{{ record.host.hostname }}"
            "{% elif record.host_set %}{{ record.host_set.name }}"
            "{% elif record.domain %}{{ record.domain.name }}"
            "{% else %}—{% endif %}"
        ),
        verbose_name="Область",
        orderable=False,
    )
    is_active = tables.BooleanColumn(verbose_name="Активен")
    actions = tables.TemplateColumn(
        template_name="credentials/_actions.html",
        orderable=False, verbose_name="",
    )

    class Meta:
        model = Credential
        fields = ("name", "kind", "username", "scope", "is_active", "actions")
        attrs = {"class": "table table-zebra table-sm w-full"}
        per_page = 50
        empty_text = "Учётных данных нет"

    def render_name(self, record):
        url = reverse("credentials:edit", args=[record.pk])
        return format_html('<a href="{}" class="link">{}</a>', url, record.name)