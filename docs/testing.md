# Тесты UI: что проверять

Тесты **не должны** зависеть от:

- локализованного текста (`"Войти"`, `"MFA"`);
- разметки allauth-ui (имена полей, action, ссылки);
- версии allauth-ui.

Тесты **должны** проверять:

- `r.status_code` (200/302/403/404);
- наличие **нашего** контракта: `data-theme`, `csrfmiddlewaretoken`;
- `r.redirect_chain` для редиректов (куда);
- `r.context["form"]` — если pytest-django даёт контекст;
- **наш** `base.html` рендерится (маркер в HTML).

Для allauth-ui — **один** smoke-тест «страница доступна» (200).
Не дублировать проверки allauth-ui.

## Тесты ошибок формы

Не проверять локализованный текст («уже привязан»).
Проверять `form.errors` или факт (объект не создан).

Правильный паттерн:
    assert r.status_code == 200
    assert r.context["form"].errors
    # или конкретное поле:
    assert "fingerprint" in r.context["form"].errors
    # или non-field:
    assert r.context["form"].non_field_errors()

Если в форме ошибка привязана к полю (`clean_<field>`) —
`form.errors[<field>]`. Если к форме (`clean`) —
`form.errors["__all__"]` или `form.non_field_errors()`.
