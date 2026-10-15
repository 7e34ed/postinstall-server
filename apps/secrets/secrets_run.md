# Выполнить

```bash
# 1. Создать .env из примера, заполнить DJANGO_SECRET_KEY
cp .env.example .env
python -c "from django.core.management.utils import get_random_secret_key as k; print(k())"
# → вставить в DJANGO_SECRET_KEY

# 2. Подготовить каталог для ключа
mkdir -p .secrets && chmod 700 .secrets
touch .secrets/master.key && chmod 600 .secrets/master.key

# 3. Поднять инфраструктуру
docker compose -f docker-compose.dev.yml up -d postgres redis openbao

# 4. Миграции (создать с нуля)
uv run python manage.py makemigrations secrets
docker compose -f docker-compose.dev.yml exec django \
    uv run python manage.py migrate

# 5. Инициализация
docker compose -f docker-compose.dev.yml exec django \
    uv run python manage.py secrets init
# → запросит ключ дважды, создаст ServerKey

# Скопировать ключ в .secrets/master.key (вручную)

# 6. Перезапуск с ключом
docker compose -f docker-compose.dev.yml up -d django celery-worker celery-beat

# 7. Проверка
curl -s http://127.0.0.1:8000/api/v1/health | jq
# → {"status":"ok","secrets":{"state":"unsealed","active_backend":"local"},...}

# 8. Тесты
uv run pytest -v tests/test_secrets_*.py
```
