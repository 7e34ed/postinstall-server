# Идеи для развития и рефакторинга

## Граф зависимостей (визуал)

**django-dependency-map** — визуализация

**Панель в Django Debug Toolbar**. Показывает граф app-зависимостей, циклы, import-linter violations (если настроен). Только для dev.

**depcycle / dependenpy / dependaman** — CLI

Быстро построить граф:

```bash
depcycle apps/ --format svg --output deps.svg
```

Плюсы: без настройки, PNG/SVG.
Минусы: не проверяет архитектуру, только визуализирует.

## A261 — унифицировать хелперы ролей в тестах

- `_assign` (локальный в test_access_hierarchy.py, matrix, access)
- `add_role` (tests/helpers.py)
Привести к одному. Сделать после того, как все тесты зелёные.
