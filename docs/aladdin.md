# RADIUS / Aladdin 2FA Server

## Что это

Интеграция с внешним RADIUS-сервером для HOTP-аутентификации
(Aladdin 2FA Server или совместимый).

Схема:

```text

Django ──[UDP Access-Request]──> RADIUS (Aladdin) ──> AD/LDAP
▲ │
└──────[Access-Accept/Reject]─────────┘
```

Пользователь вводит **username** и **пароль+OTP** (конкатенация).
Aladdin парсит последние 6 цифр как HOTP, остальное — как пароль
(в AD/LDAP). При успехе возвращает Access-Accept.

## Что нужно от заказчика

1. **Развёрнутый Aladdin 2FA Server** или совместимый RADIUS.
2. **Shared secret** для нашего сервера (в Aladdin: «RADIUS-клиент»).
3. **Разрешённый IP** нашего сервера в Aladdin (ACL RADIUS-клиентов).
4. **HOTP-токены**, привязанные к пользователям в Aladdin.
5. Доступность по **UDP:1812** между Django и RADIUS.

## Что нужно на нашей стороне

В constance:

| Параметр | Пример | Описание |
| --- | --- | --- |
| `AUTH_RADIUS_ENABLED` | true | Включить |
| `AUTH_RADIUS_HOST` | 10.0.0.50 | IP RADIUS-сервера |
| `AUTH_RADIUS_PORT` | 1812 | UDP-порт |
| `AUTH_RADIUS_SECRET` | (secret) | Shared secret |
| `AUTH_RADIUS_NAS_ID` | postinstall.local | NAS-Identifier |
| `AUTH_RADIUS_TIMEOUT` | 3 | Секунды |
| `AUTH_RADIUS_RETRIES` | 2 | Повторы |
| `AUTH_RADIUS_FAIL_OPEN` | **false** | При недоступности RADIUS — отказ |

`AUTH_RADIUS_FAIL_OPEN` в проде должен быть `false`: если RADIUS лёг,
пользователи не входят. `true` — только для break-glass-сценария,
когда нужно хоть как-то зайти.

## Перевод пользователя на RADIUS

1. Убедиться, что пользователь создан в Django (по инвайту).
2. В админке `/admin/access/userauthsettings/` создать запись:
   - user: alice
   - auth_source: radius
   - radius_username: (опционально, если отличается)
3. Пользователь входит: `username=alice, password=<AD-пароль><HOTP>`.

После этого локальный пароль Django **не работает** для этого
пользователя. Если нужно вернуть — сменить `auth_source` обратно
на `local`.

## Проверка

Из UI: `/access/radius/` → «Проверка соединения».

Из шелла:

```bash
manage.py shell -c "
from apps.access.auth_backends import build_config_from_constance, test_connection
cfg = build_config_from_constance()
print(cfg)
r = test_connection(cfg, username='alice', password='secret123456')
print(r)
"
```

Из **CLI** (для отладки без Django):

```bash
radtest alice secret123456 10.0.0.50 0 <shared_secret>
```

## Развёртывание RADIUS-сервера (справка)

Если заказчик не имеет **Aladdin**, но хочет **HOTP**:

1. FreeRADIUS + Google Authenticator PAM (как клиент) — бесплатно, работает
    с **HOTP**/**TOTP**:

    ```bash
    apt install freeradius freeradius-utils libpam-google-authenticator
    ```

    В `/etc/freeradius/3.0/users`:

    ```text
    alice Cleartext-Password := "password"
    Auth-Type := PAM
    ```

    В PAM-конфиге включить **pam_google_authenticator.so**.
2. **Aladdin 2FA Server** — коммерческий, с интеграцией в AD.
3. **PrivacyIDEA** — open-source, с поддержкой `HOTP/TOTP/WebAuthn`.

## Диагностика

Логи:

```bash
cat /var/log/postinstall/server.log | grep radius
```

Типичные проблемы:

- `radius: timeout для <user>` — UDP 1812 недоступен. Проверить nc -u -z RADIUS_IP 1812.
- `radius: Access-Reject` — пароль или OTP неверны.
- `radius: <user> inactive` — пользователь отключён в Django.
- `radius: пользователь не radius` — auth_source=local. Изменить в админке.

## Ручная проверка (при наличии RADIUS в сети)

1. В `/admin/constance/config/` включить `AUTH_RADIUS_ENABLED=True`,
заполнить `host/port/secret`.
2. `/access/radius/` → «Проверка соединения».
3. Перевести тестового пользователя на `auth_source=radius`.
4. Войти `username+password+OTP`.