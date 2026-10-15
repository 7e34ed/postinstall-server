# Секреты

Создание файла ключа:

```bash
mkdir -p .secrets
touch .secrets/master.key
chmod 600 .secrets/master.key
# вписать туда мастер-ключ после первого init
```

Порядок первого запуска:

1. `docker compose ... up -d postgres redis openbao`
2. `docker compose ... run --rm django uv run python manage.py migrate`
3. `docker compose ... run --rm django uv run python manage.py secrets init`
   - запросит мастер-ключ;
   - скопировать его в .secrets/master.key (или запускать init так, чтобы он сам сохранил — но у нас пока ручной путь);
4. `docker compose ... up -d`
