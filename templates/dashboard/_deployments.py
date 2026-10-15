{% if recent %}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <thead>
        <tr>
          <th>ID</th>
          <th>Хост</th>
          <th>Домен</th>
          <th>Статус</th>
          <th>Создан</th>
          <th>Завершён</th>
        </tr>
      </thead>
      <tbody>
        {% for d in recent %}
          <tr>
            <td class="font-mono text-xs">
              <a href="{% url 'deploy:detail' d.id %}" class="link">
                {{ d.id|slice:":8" }}
              </a>
            </td>
            <td>
              <a href="{% url 'inventory:host-detail' d.host.pk %}" class="link">
                {{ d.host.hostname }}
              </a>
            </td>
            <td class="text-xs opacity-70">{{ d.host.domain.name }}</td>
            <td>{% include "deploy/_badge.html" with status=d.status %}</td>
            <td class="text-xs">{{ d.created_at|date:"Y-m-d H:i:s" }}</td>
            <td class="text-xs">{{ d.finished_at|date:"Y-m-d H:i:s"|default:"—" }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% else %}
  <p class="text-sm opacity-60">Развёртываний пока не было.</p>
{% endif %}