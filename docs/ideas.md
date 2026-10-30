# Граф зависимостей (визуал)
**django-dependency-map** — визуализация

**Панель в Django Debug Toolbar**. Показывает граф app-зависимостей, циклы, import-linter violations (если настроен). Только для dev.

**depcycle / dependenpy / dependaman** — CLI

Быстро построить граф:
```bash
depcycle apps/ --format svg --output deps.svg
```

Плюсы: без настройки, PNG/SVG.
Минусы: не проверяет архитектуру, только визуализирует.



