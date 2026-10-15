import json

from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
def pretty_json(value):
    try:
        return mark_safe(json.dumps(value, indent=2, ensure_ascii=False))
    except (TypeError, ValueError):
        return str(value)