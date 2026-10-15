# postinstall-server

Source of truth для управления парком хостов: инвентарь, конфиги,
hardening, секреты, деплой. Отдаёт агентам `psi-agent` отрендеренный
JSON-конфиг.

## Стек

- Django 5, DRF, drf-spectacular
- Postgres 16, Redis 7, Celery
- Unfold (админка), Guardian (permissions), Constance (настройки),
  django-vite + Alpine + HTMX + Tailwind + daisyUI
- loguru
- Статика: whitenoise (dev) или S3 (prod) — переключается `STATIC_STORAGE`

## Быстрый старт

```bash
cp .env.example .env
python -c "from django.core.management.utils import get_random_secret_key as k; print(k())"
# вставьте значение в DJANGO_SECRET_KEY

docker compose -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.dev.yml exec django python manage.py migrate
docker compose -f docker-compose.dev.yml exec django python manage.py createsuperuser
```

Открыть:

- UI: `http://localhost:8000/`
- Админка: `http://localhost:8000/admin/`
- API schema: `http://localhost:8000/api/docs/`
- Health: `http://localhost:8000/api/v1/health`

## Frontend

```bash
cd frontend
npm install
npm run dev      # dev-сервер Vite на 127.0.0.1:5173
npm run build    # сборка в ../static/dist/
```

В dev `DJANGO_VITE.dev_mode = true`, ассеты тянутся с Vite dev-сервера.
В prod `dev_mode = false`, всё берётся из `static/dist/.vite/manifest.json`.

## Что уже есть

- Модели `Domain`, `HostSet`, `Host` с JSONB-полями.
- Guardian ACL (по домену).
- AuditLog + middleware на write-запросы.
- Список хостов с django-tables2 + django-filters + HTMX.
- Unfold-админка.
- Celery + beat (без задач пока).
- OpenAPI через drf-spectacular.
- Health-check `/api/v1/health`.

## Что дальше

1. **API агентов** — `/register`, `/heartbeat`, `/tasks`, `/report`.
   См. контракт `RenderedConfig` в репозитории `psi-agent`.
2. **Модуль `config`** — `ConfigProfile`, `ConfigRevision`, `Repository`,
   `Certificate`.
3. **Модуль `hardening`** — каталог проверок, `HardeningPolicy`.
4. **Модуль `secrets`** — OpenBao / KeePass / Local.
5. **Модуль `deploy`** — `Deployment`, `DeploymentRun`, `Agent`,
   `AgentHeartbeat`.
6. **Ansible-runner** + динамический inventory из БД.
7. **LDAP-синк** через `ldap3`.
8. **UI** — рабочие экраны для всего выше.

## Dev-заметки

- Postgres и Redis — в `docker-compose.dev.yml` (loopback).
- Для CI-стенда — `docker-compose.ci.yml` (два фейковых Linux-таргета).
- Прод разворачивается в k8s (манифесты — отдельно).

## Bootstrap и модель доверия

В приложении ровно **два секрета вне БД**:

1. **`DATABASE_URL`** — стандартная практика; в проде обычно кладётся в
   k8s Secret и монтируется как env.
2. **Мастер-ключ шифрования** (`SECRETS_MASTER_KEY_FILE` / `FD` / `ENV`) —
   единственный «корень доверия». Никогда не хранится в БД.

Всё остальное — credentials OpenBao, KeePass-пароль, прикладные секреты —
лежит в **едином зашифрованном блобе** в таблице `ServerKey`. Блоб шифруется
мастер-ключом через Argon2id + AES-GCM.

### Потеря мастер-ключа

Потеря = безвозвратная потеря всех секретов: credentials OpenBao, паролей
домена, всего. Поэтому:

- мастер-ключ хранится в двух независимых местах;
- в проде используется `FILE` или `FD` (не `ENV`);
- ротация выполняется командой `manage.py secrets rotate`, которая требует
  старый и новый ключ одновременно.

### Состояния

| Состояние       | Что значит                             | `/health` |
|-----------------|----------------------------------------|-----------|
| `uninitialized` | `ServerKey` ещё не создан              | 200       |
| `sealed`        | `ServerKey` есть, ключа в памяти нет   | 503       |
| `unsealed`      | Блоб расшифрован, секреты доступны     | 200       |

При `sealed` middleware отдаёт 503 на всё, кроме `/admin/secrets/unlock/`,
`/admin/login/`, `/api/v1/health`, `/static/`. Штатно приложение
разблокируется при старте через `FILE`; UI-unlock — аварийный путь.

### Смена backend

Active backend хранится **внутри блоба** (ключ `active_backend`). Никаких
env-переменных. Смена — через `/admin/secrets/backend/` или
`manage.py secrets backend set <name>`. Перед переключением выполняется
health-check нового backend; при неудаче переключение отклоняется.

### Credentials backend'ов

Хранятся в блобе под `backend_credentials/<name>`. Значения видны только
при разблокированном runtime; в UI маскируются. Все изменения пишутся в
`SecretAccessLog`.

См. также `docs/openbao.md` для прод-развёртывания OpenBao.