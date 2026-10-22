{% extends "admin/base_site.html" %}
{% load i18n %}

{% block content %}
<div style="max-width: 1000px;">

  <div style="display:flex; justify-content:space-between; align-items:center;">
    <h1>Секреты</h1>
    <a class="button default" href="{% url 'secrets:item-new' %}">+ Создать</a>
  </div>

  {% if messages %}
    {% for m in messages %}
      <div class="{% if m.tags == 'error' %}errornote{% else %}messagelist{% endif %}">
        {{ m }}
      </div>
    {% endfor %}
  {% endif %}

  <form method="get" style="margin: 1rem 0;">
    <input type="text" name="q" value="{{ q }}" placeholder="Поиск по пути…"
           style="padding: 6px; width: 300px; font-family: monospace;">
    <button type="submit" class="button">Найти</button>
    {% if q %}<a href="{% url 'secrets:items' %}" class="button">Сбросить</a>{% endif %}
  </form>

  {% if rows %}
    <table class="table" style="width: 100%; border-collapse: collapse;">
      <thead>
        <tr style="background: #242b34;">
          <th style="padding: 6px; text-align: left;">Путь</th>
          <th style="padding: 6px;">Ключей</th>
          <th style="padding: 6px; text-align: left;">Ключи</th>
          <th style="padding: 6px;"></th>
        </tr>
      </thead>
      <tbody>
        {% for r in rows %}
          <tr style="border-top: 1px solid #333;">
            <td style="padding: 6px; font-family: monospace;">
              <a href="{% url 'secrets:item-edit' r.path %}">{{ r.path }}</a>
            </td>
            <td style="padding: 6px; text-align: center;">{{ r.key_count }}</td>
            <td style="padding: 6px; opacity: .7; font-size: .9em;">
              {{ r.keys|join:", "|truncatechars:80 }}
            </td>
            <td style="padding: 6px; text-align: right; white-space: nowrap;">
              <a href="{% url 'secrets:item-edit' r.path %}"
                 class="button">Открыть</a>
              <form method="post"
                    action="{% url 'secrets:item-delete' r.path %}"
                    style="display:inline-block;"
                    onsubmit="return confirm('Удалить запись {{ r.path }} целиком?');">
                {% csrf_token %}
                <button type="submit" class="button"
                        style="background:#7f1d1d;">Удалить</button>
              </form>
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% else %}
    <p style="opacity: .6;">
      {% if q %}Ничего не найдено по запросу «{{ q }}».{% else %}Секретов пока нет.{% endif %}
    </p>
  {% endif %}

  <p style="margin-top: 2rem;">
    <a href="{% url 'secrets:backend' %}">← К настройкам backend</a>
  </p>

</div>
{% endblock %}