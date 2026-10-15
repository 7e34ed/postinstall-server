# 1. Создать приложение

# 2. Сгенерировать миграции

`uv run python manage.py makemigrations access`

# 3. Создать data-миграцию (вручную) — файл 0002_bootstrap_existing.py

# 4. Применить

`uv run python manage.py migrate`

# 5. Проверки

`uv run python manage.py check`

# 6. Тесты

`uv run pytest -v tests/test_access.py`

# 7. Dev: если в системе <2 superuser'ов — приложение перейдёт в setup-фазу

# Открыть http://localhost:8000/