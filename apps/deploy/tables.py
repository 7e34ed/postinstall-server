import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html

from .models import Deployment


class DeploymentTable(tables.Table):
    id = tables.Column(verbose_name="ID", orderable=False)
    host = tables.Column(accessor="host.hostname", verbose_name="Хост",
                         linkify=False)
    status = tables.TemplateColumn(
        template_name="deploy/_status_badge.html",
        verbose_name="Статус",
        orderable=True,
    )
    priority = tables.Column(verbose_name="Приоритет")
    created_at = tables.DateTimeColumn(format="Y-m-d H:i", verbose_name="Создан")
    dispatched_at = tables.DateTimeColumn(format="Y-m-d H:i", verbose_name="Отправлен")
    finished_at = tables.DateTimeColumn(format="Y-m-d H:i", verbose_name="Завершён")

    class Meta:
        model = Deployment
        fields = ("id", "host", "status", "priority", "created_at",
                  "dispatched_at", "finished_at")
        attrs = {"class": "table table-zebra table-sm w-full"}
        per_page = 50
        empty_text = "Развёртываний не найдено"

    def render_id(self, record):
        url = reverse("deploy:detail", args=[record.id])
        return format_html(
            '<a href="{}" class="link link-primary font-mono text-xs">{}</a>',
            url, str(record.id)[:8],
        )

    def render_host(self, record):
        url = reverse("inventory:host-detail", args=[record.host.pk])
        return format_html(
            '<a href="{}" class="link">{}</a>',
            url, record.host.hostname,
        )