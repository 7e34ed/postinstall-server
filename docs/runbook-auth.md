# Runbook: аутентификация и доступ

Сборник аварийных процедур. Для каждой ситуации — симптом, немедленные
действия, что делать после восстановления.

## Индекс

1. Потерян пароль SUPERVISOR'а
2. Потерян MFA (TOTP) у пользователя
3. Потерян WebAuthn-ключ
4. Потерян клиентский сертификат / токен
5. Компрометация учётной записи
6. Все SUPERVISOR'ы потеряли доступ
7. Подозрение на tamper (вмешательство) audit-логов
8. Нужно срочно отключить доступ одному пользователю
9. Массовое отключение доступа (увольнение)
10. Забыт пароль break-glass
11. IP-allowlist блокирует офис
12. Отключение MFA принуждения для одного пользователя

---

## 1. Потерян пароль SUPERVISOR'а

**Симптом.** Пользователь не может войти, пароль не подходит.

**Действия:**

1. Если у пользователя есть активная сессия в другом браузере —
   сменить пароль через UI `/accounts/password/change/`.

2. Если активной сессии нет — второй SUPERVISOR через
   `manage.py shell`:

   ```python
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   u.set_password('новый-временный-пароль')
   u.save()
   ```

   Передать пароль пользователю по защищённому каналу. Пользователь
   обязан сменить пароль при первом входе.

3. Если второго SUPERVISOR'а нет — см. п. 6 (break-glass).

**Аудит.** Все события в `/admin/access/authauditlog/`, фильтр по
`user=ivan`.

---

## 2. Потерян MFA (TOTP) у пользователя

**Симптом.** Пользователь не может пройти challenge — нет доступа
к приложению-аутентификатору.

**Действия:**

1. Если у пользователя сохранены recovery codes — зайти с ними.
   После входа — перевыпустить TOTP.

2. Если recovery codes тоже потеряны — SUPERVISOR отключает TOTP:

   ```bash
   manage.py shell -c "
   from allauth.mfa.models import Authenticator
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   deleted = Authenticator.objects.filter(user=u, type='totp').delete()
   print('deleted:', deleted)
   "
   ```

   Пользователь логинится паролем, заново настраивает TOTP.

**Аудит.** Событие `MFA_DISABLED` от SUPERVISOR'а, который удалил фактор.

---

## 3. Потерян WebAuthn-ключ

**Симптом.** Пользователь потерял YubiKey / Passkey / смартфон.

**Действия:**

1. Если есть backup WebAuthn-ключ — зайти с ним.
2. Если есть recovery codes — зайти с ними.
3. Иначе — SUPERVISOR удаляет WebAuthn-фактор:

   ```bash
   manage.py shell -c "
   from allauth.mfa.models import Authenticator
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   Authenticator.objects.filter(user=u, type='webauthn').delete()
   "
   ```

4. Если у пользователя был только hardware (без TOTP) — после удаления
   WebAuthn он падает на AAL1. Рекомендуется сразу добавить новый
   hardware или TOTP.

**Компрометация ключа.** Если ключ украден — отозвать его у всех
сервисов (не только у нас), затем удалить фактор. См. п. 5.

---

## 4. Потерян клиентский сертификат / токен

**Симптом.** Пользователь потерял Rutoken / JaCarta / файл `.p12`.

**Действия:**

1. Отозвать сертификат через UI `/access/security/certificates/`:
   - открыть запись;
   - нажать «Отозвать»;
   - указать причину.

2. Выпустить новый сертификат через УЦ (вне нашего приложения).

3. Пользователь привязывает новый сертификат.

**Если сертификат был на hardware.** Дополнительно отозвать сам
носитель через УЦ (CRL). Nginx проверяет подпись, но CRL мы на
своей стороне не проверяем — отзыв в Django означает отказ в доступе,
но CRL всё равно стоит обновить.

**Аудит.** `CERT_REVOKED` + `CERT_ADDED`.

---

## 5. Компрометация учётной записи

**Симптом.** Подозрение, что пароль утёк; либо пользователь сам
заявил об этом.

**Действия (в течение 15 минут):**

1. **Немедленно** — деактивировать пользователя:

   ```python
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   u.is_active = False
   u.save()
   ```

   Все активные сессии перестанут работать при следующем запросе.

2. Отозвать все `RoleAssignment` пользователя:

   ```bash
   manage.py shell -c "
   from apps.access.models import RoleAssignment
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   from django.utils import timezone
   RoleAssignment.objects.filter(user=u, revoked_at__isnull=True).update(
       revoked_at=timezone.now(), revoke_reason='compromise'
   )
   "
   ```

3. Отозвать все MFA-факторы:

   ```bash
   manage.py shell -c "
   from allauth.mfa.models import Authenticator
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   Authenticator.objects.filter(user=u).delete()
   "
   ```

4. Отозвать все сертификаты пользователя:

   ```bash
   manage.py shell -c "
   from apps.access.models import UserCertificate
   from apps.access.services import ...  # или просто пометить is_active=False
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   UserCertificate.objects.filter(user=u).update(is_active=False)
   "
   ```

5. Проверить `AuthAuditLog` за последние 24 часа на его логины
   с необычных IP:

   ```sql
   SELECT created_at, event, ip, user_agent
   FROM access_authauditlog
   WHERE user_id = (SELECT id FROM auth_user WHERE username='ivan')
     AND created_at > NOW() - INTERVAL '24 hours'
   ORDER BY created_at DESC;
   ```

6. Уведомить руководителя ИБ.

7. **После разбора** — при необходимости создать новую учётку
   (не восстанавливать старую).

---

## 6. Все SUPERVISOR'ы потеряли доступ

**Симптом.** Ни один SUPERVISOR не может войти. Критическая ситуация.

**Действия:**

1. Убедиться, что нет активных SUPERVISOR'ов за последние 24 ч:

   ```bash
   manage.py break_glass status
   ```

2. Включить break-glass (с физического доступа к серверу):

   ```bash
   sudo -u postinstall python manage.py break_glass enable \
       --reason "все SUPERVISOR'ы потеряли доступ, восстановление"
   ```

   Если система отказывает «есть живые SUPERVISOR'ы» — использовать
   `--force` только с подтверждения руководителя ИБ.

3. Войти как `break-glass` с паролем из recovery kit (физический сейф).

4. Создать нового SUPERVISOR'а:
   - через `/access/invites/new/` (инвайт);
   - либо через `manage.py bootstrap_supervisor <username>` (двух раз).

5. Создать второго SUPERVISOR'а.

6. Восстановить других пользователей по мере необходимости.

7. Выключить break-glass:

   ```bash
   manage.py break_glass disable
   ```

**Аудит.** Все шаги логируются. Уведомления всем SUPERVISOR'ам —
если они есть в БД (пусть и не могут войти).

См. `docs/break-glass.md` для полной процедуры.

---

## 7. Подозрение на tamper (вмешательство) audit-логов

**Симптом.** Верификация не проходит; кто-то мог изменить `AuditLog`
или `AuthAuditLog`.

**Действия:**

1. Запустить верификацию:

   ```bash
   manage.py verify_audit
   ```

   Вывод покажет `broken_at=<id>` — первую повреждённую запись.

2. Определить диапазон повреждения. Проверить:
   - прямые SQL-изменения (кто имеет доступ к БД);
   - обход append-only через DB-триггер;
   - восстановление из бэкапа.

3. Сохранить доказательства:

   ```bash
   manage.py export_audit --file /tmp/audit-incident-$(date +%s).jsonl
   ```

   Файл скопировать в защищённое место (не на изменяемый сервер).

4. Проверить `AuditVerifyRun` — последние прогоны, есть ли
   закономерность.

5. Уведомить руководителя ИБ. Инцидент — критический.

6. Оценить масштаб:
   - какие именно записи повреждены;
   - за какой период;
   - какие действия они описывали.

7. **Не восстанавливать** записи из бэкапа поверх — это скроет факт
   tamper. Все дальнейшие действия — по указанию ИБ.

---

## 8. Нужно срочно отключить доступ одному пользователю

**Быстрая процедура (2 минуты):**

```bash
manage.py shell -c "
from django.contrib.auth import get_user_model
from apps.access.models import RoleAssignment
from django.utils import timezone

User = get_user_model()
u = User.objects.get(username='ivan')
u.is_active = False
u.save()
RoleAssignment.objects.filter(user=u, revoked_at__isnull=True).update(
    revoked_at=timezone.now(), revoke_reason='urgent revoke'
)
print('disabled:', u.username)
"
```

Пользователь не сможет зайти; активные сессии оборвутся при следующем
запросе.

**Отличие от п. 5.** Здесь пароль сохранён, MFA не трогаем — только
блокируем. Можно быстро вернуть (`is_active=True` + переназначить роли).

---

## 9. Массовое отключение (увольнение)

**Сценарий.** Увольняется сотрудник с несколькими ролями.

1. Остановить активные deployment-задачи пользователя:

   ```bash
   manage.py shell -c "
   from apps.deploy.models import Deployment
   from apps.deploy.services import cancel_bulk
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   active = Deployment.objects.filter(
       created_by=u, status__in=['pending','dispatched','running']
   )
   for d in active:
       d.status = 'cancelled'
       d.save()
   print('cancelled:', active.count())
   "
   ```

2. Отозвать все роли (см. п. 5, шаг 2).

3. Отозвать все MFA (шаг 3).

4. Отозвать все сертификаты (шаг 4).

5. Деактивировать:

   ```bash
   manage.py shell -c "
   from django.contrib.auth import get_user_model
   User = get_user_model()
   User.objects.filter(username='ivan').update(is_active=False)
   "
   ```

6. Изменить владельца всех секретов и credentials, где он был owner:

   ```bash
   manage.py shell -c "
   from apps.secrets.models import SecretRef
   from apps.credentials.models import Credential
   from django.contrib.auth import get_user_model
   User = get_user_model()
   u = User.objects.get(username='ivan')
   # передать владение на SUPERVISOR'а через UI-функцию transfer_ownership
   # для каждого секрета:
   secrets = SecretRef.objects.filter(owner=u)
   print('secrets to transfer:', secrets.count())
   # затем через /admin/secrets/items/ проверить и передать вручную
   "
   ```

   Каждая передача — двухстороннее подтверждение (см. `docs/roles.md`).

7. Сохранить отчёт:

   ```bash
   manage.py export_audit --file /tmp/offboarding-ivan-$(date +%s).jsonl
   ```

---

## 10. Забыт пароль break-glass

**Симптом.** Recovery kit утерян или пароль не помнится.

**Действия:**

1. Создать новый kit:

   ```bash
   sudo -u postinstall python manage.py break_glass reset-kit --out /tmp/
   ```

   Создаст новую учётку с новым паролем, старые recovery codes сгорят.

2. Сохранить kit в физический сейф.

3. Старый kit уничтожить.

**Если нужно только узнать, что учётка существует:**

```bash
manage.py break_glass status
```

Покажет состояние без пароля.

---

## 11. IP-allowlist блокирует офис

**Симптом.** Все сотрудники одного офиса получают 403 «Доступ ограничен
по IP».

**Действия:**

1. Определить, какое правило блокирует:

   ```bash
   manage.py shell -c "
   from apps.access.models import IPAllowlistRule
   for r in IPAllowlistRule.objects.filter(is_active=True):
       print(r.scope, r.user_id, r.role, r.cidr)
   "
   ```

2. Добавить правильный IP офиса:
   - через UI `/access/ip-rules/` → добавить правило (scope=USER для
     конкретного, scope=GLOBAL для всех);
   - либо через shell:

     ```python
     IPAllowlistRule.objects.create(
         scope='global', cidr='203.0.113.0/24',
         description='офис Москва, добавлено ' + str(timezone.now()),
     )
     ```

3. Проверить снаружи:

   ```bash
   curl -I https://postinstall.local/ --resolve postinstall.local:443:1.2.3.4
   ```

**Отключить правило полностью:**

```python
IPAllowlistRule.objects.filter(cidr='...').update(is_active=False)
```

**Отключить правило для одного пользователя:**

```python
IPAllowlistRule.objects.filter(
    scope='user', user__username='ivan'
).delete()
```

---

## 12. Отключение MFA принуждения для одного пользователя

**Симптом.** Пользователь не может завершить setup MFA (проблемы с
телефоном), но при этом важен для работы.

**Временное решение.** Увеличить grace period для пользователя:

```bash
manage.py shell -c "
from apps.access.models import UserActivity
from django.contrib.auth import get_user_model
from django.utils import timezone
User = get_user_model()
u = User.objects.get(username='ivan')
act, _ = UserActivity.objects.get_or_create(user=u)
act.mfa_first_seen_at = timezone.now()   # сбрасывает таймер
act.save()
print('grace reset for', u.username)
"
```

Или отключить требование через constance (действует на всех):

```python
from constance import config
config.MFA_REQUIRED_FOR_OPERATOR = False
```

**Постоянное решение.** Пользователь подключает MFA. Если роль
не требует MFA (VIEWER/OPERATOR) — принуждение уже не действует.

**Не рекомендуется.** Отключать принуждение глобально, если политика
безопасности требует MFA.

---

## Связанные документы

- `docs/auth.md`
- `docs/roles.md`
- `docs/mfa.md`
- `docs/break-glass.md`
- `docs/mtls.md`
- `docs/pkcs11.md`
- `docs/aladdin.md`
