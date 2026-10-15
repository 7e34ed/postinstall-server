import django_tables2 as tables

from .models import ConfigProfile


class ProfileTable(tables.Table):
    name = tables.Column(linkify=False, verbose_name="Профиль")
    slug = tables.Column(verbose_name="Slug")
    platform = tables.Column(verbose_name="Платформа")
    version = tables.Column(verbose_name="Версия")
    is_active = tables.BooleanColumn(verbose_name="Активен")
    updated_at = tables.DateTimeColumn(format="Y-m-d H:i", verbose_name="Обновлён")
    actions = tables.TemplateColumn(
        template_name="config/_profile_actions.html",
        orderable=False,
        verbose_name="",
        attrs={"td": {"class": "text-right whitespace-nowrap"}},
    )

    class Meta:
        model = ConfigProfile
        fields = ("name", "slug", "platform", "version", "is_active",
                  "updated_at", "actions")
        attrs = {
            "class": "table table-zebra table-sm w-full",
            "thead": {"class": "bg-base-200"},
        }
        per_page = 50
        empty_text = "Профилей не найдено"