# Аутентификация

Документ описывает общую модель аутентификации в postinstall-server:
принципы, способы входа, уровни AAL, сессии, аудит. Детали по каждому
методу — в отдельных документах, ссылки в конце.

## Принципы

1. **Access by invitation only.** Никакой самрегистрации. Первый
   пользователь создаётся при setup, все остальные — через инвайт.

2. **Authentication ≠ Authorization.** Способы входа (пароль, TOTP,
   сертификат, токен) и права (роли, scope) — независимые слои.
   Меняются независимо.

3. **AAL — единая ось.** Все способы входа приводятся к трём уровням
   Authenticator Assurance Level. Проверки во всех view работают
   с AAL, а не с конкретным методом.

4. **Каждое действие — с аудитом.** Всё пишется в `AuthAuditLog`
   (append-only, hash chain, см. `docs/tamper.md`).

5. **Fail-closed по умолчанию.** Если внешний фактор (RADIUS, mTLS)
   недоступен — отказ, а не разрешение. Обход только через явные
   аварийные механизмы (`break-glass`).

## Способы аутентификации

| Способ | Пакет/реализация | AAL | Документ |
| --- | --- | --- | --- |
| Пароль | django.contrib.auth | AAL1 | этот документ |
| TOTP | allauth.mfa | AAL2 | `mfa.md` |
| Recovery codes | allauth.mfa | AAL2 | `mfa.md` |
| WebAuthn / FIDO2 | allauth.mfa | AAL3 | `mfa.md` |
| Client certificate (mTLS) | reverse proxy + middleware | AAL3 | `mtls.md` |
| Rutoken ECP | через mTLS или WebAuthn | AAL3 | `pkcs11.md` |
| RADIUS / Aladdin HOTP | pyrad + RadiusBackend | AAL2 | `aladdin.md` |

**Про пароль.** Пароль — базовый метод и часть AAL1. Пароль **не может
быть единственным** фактором для SUPERVISOR/ADMIN, если включён
`AUTH_HIGH_SECURITY_MODE` (см. ниже). Для младших ролей — допустимо,
но рекомендуется TOTP.

## Уровни AAL

### AAL1 — один фактор

Достигается логином с паролем. Сессия помечается AAL1 при успешном
логине.

### AAL2 — два фактора

Пароль + второй фактор (TOTP, recovery code, RADIUS HOTP).

### AAL3 — два фактора, hardware

Пароль + hardware-фактор:

- WebAuthn (FIDO2-ключ);
- клиентский сертификат на аппаратном носителе (Rutoken, JaCarta, eToken);
- любой другой hardware, который работает через один из этих каналов.

Программные сертификаты (файл `.p12`) **не считаются AAL3** — их можно
скопировать, поэтому они классифицируются как AAL2.

### Как AAL определяется для сессии

При логине:

- allauth password login → AAL1;
- allauth password login (для пользователя с `auth_source=radius`) → AAL2;
- mTLS auto-login → AAL3;
- break-glass login → AAL3.

При reauth (повторное подтверждение):

- после MFA reauthenticate → AAL2;
- если у пользователя есть hardware → AAL3.

При изменении MFA пользователя (например, отключил TOTP) — текущая
сессия может потерять уровень: `current_aal()` ограничивается тем,
что реально доступно пользователю сейчас.

### Где AAL проверяется

- **`AalEnforcementMiddleware`** — на уровне URL. Если URL в
  `AAL_REQUIREMENTS` требует AAL выше, чем есть в сессии — редирект
  на reauthenticate.
- **`@require_aal(...)`** — декоратор для точечных view.
- **`@require_aal_action("...")`** — по имени логического действия.

### Session upgrade

Если пользователю нужен AAL выше текущего — сессия **не** перезагружается
полностью. Пользователь попадает на `/accounts/reauthenticate/`,
подтверждает личность (ввод TOTP, предъявление токена), после чего
уровень сессии поднимается на 15 минут (`AUTH_AAL_UPGRADE_TTL`).

Через 15 минут — снова редирект на reauth для критичных действий.
Сессия при этом не теряется.

### Реестр требований

Полный список `path → AAL` — в `apps/access/aal.py:AAL_REQUIREMENTS`.
Ключевые значения:

| Действие | AAL |
| --- | --- |
| Просмотр хостов, профилей, deployments | AAL1 |
| Список ролей | AAL2 |
| Создание deployment | AAL2 |
| Изменение профиля | AAL2 |
| Изменение backend секретов | AAL3 |
| Изменение credentials | AAL3 |
| Назначение роли | AAL3 |
| Переключение high-security mode | AAL3 |

Требования можно переопределить в `main.json` (см. раздел
«High-security mode»).

## High-security mode

Рубильник `AUTH_HIGH_SECURITY_MODE` (constance):

- когда выключен — SUPERVISOR/ADMIN могут работать с AAL2 (TOTP).
- когда включён — для критичных операций **обязателен** hardware
  (AAL3). Если у пользователя hardware нет — при попытке такой
  операции система потребует reauthenticate через доступный AAL2
  и дополнительное двухстороннее подтверждение.

Переключение режима:

- SUPERVISOR с AAL3;
- двухстороннее подтверждение (второй SUPERVISOR);
- алерт всем SUPERVISOR'ам;
- отдельная запись в `AuthAuditLog`.

## Сессии

- Django session backend — на выбор: Redis, DB, файл. По умолчанию — Redis.
- TTL сессии — `SESSION_COOKIE_AGE` (по умолчанию 8 часов).
- Sliding renewal — каждые 5 минут активности.
- Logout — смена CSRF-токена, уничтожение сессии.
- Single-session per user — **не включено** (пользователь может быть
  в нескольких браузерах). При необходимости — `SESSION_EXPIRE_AT_BROWSER_CLOSE=True`.

## Аутентификация по API

Для API-эндпоинтов — два независимых потока:

1. **UI API** (SessionAuthentication) — работает с сессией браузера,
   проходит через `AalEnforcementMiddleware`.
2. **Agent API** — своя аутентификация по Ed25519-подписи
   (см. `api/authentication.py`). Агенты не пользователи, у них нет
   AAL и ролей; их права определяются контрактом `RenderedConfig`.
3. **Service accounts** — Bearer-токен, см. `docs/service-accounts.md`.

## Ввод в эксплуатацию (bootstrap)

Первый запуск:

1. Superuser создаётся через `manage.py createsuperuser`.
2. Приложение входит в setup-фазу (`SuperuserBootstrap.is_setup_complete=False`).
3. Superuser через UI `/access/setup/` создаёт двух SUPERVISOR'ов.
4. После создания второго SUPERVISOR'а setup завершается:
   - создаётся break-glass-учётка (неактивна);
   - генерируется recovery kit;
   - superuser блокируется (используется только для аварий).
5. Приложение переходит в обычный режим.

## Отключение доступа

- **Увольнение.** SUPERVISOR/ADMIN через UI отзывает все `RoleAssignment`
  пользователя. Сессия пользователя становится read-only (все URL с
  AAL и ролями отказывают). Опционально: деактивация `User.is_active=False`.
- **Компрометация.** Смена пароля + отзыв всех MFA-факторов +
  отзыв сертификатов. При необходимости — инцидентный разбор через аудит.

## Что не реализовано

- OIDC / SAML SSO — вне области.
- Kerberos-аутентификация напрямую — вне области.
- YubiKey OTP (не FIDO2) — не поддерживается; используйте WebAuthn.
- Mobile push (Duo, Okta Verify) — вне области.

## Связанные документы

- `docs/roles.md` — роли, scope, матрица прав.
- `docs/mfa.md` — TOTP, recovery codes, WebAuthn.
- `docs/mtls.md` — клиентские сертификаты.
- `docs/pkcs11.md` — Rutoken ECP.
- `docs/aladdin.md` — RADIUS / HOTP.
- `docs/break-glass.md` — аварийный доступ.
- `docs/runbook-auth.md` — аварийные процедуры.