# KeePass-бэкенд

KeePass-бэкенд хранит все секреты в одном `.kdbx`-файле на диске.
Подходит, когда нет желания разворачивать OpenBao, но хочется
offline-резерв и внешний аудит. **Не предназначен для больших парков.**

## Ограничения (важно прочитать до включения)

| Что | Значение |
|---|---|
| Объём | до ~200 секретов, до ~50 хостов |
| Производительность | ~50–200 мс на операцию (полная расшифровка файла) |
| Параллельная запись | **не поддерживается** между процессами |
| Несколько подов приложения | только read-only или с внешним локом |
| Сетевые FS | не рекомендуется (NFS может ломать file lock) |

Если нужен больший парк, несколько реплик или высокая нагрузка — используйте
OpenBao. KeePass — для случаев «openbao не осилят, а секреты хранить надо».

## Формат пути

path = "domains/example.local/domain_password"
→ группа domains/example.local, запись с title=domain_password
key = "password" | "username" | "url" | "notes" | "value" (custom)

Стандартные свойства KeePass: `password`, `username`, `url`, `notes`.
Произвольные — как custom property с префиксом `psi.` (чтобы не
конфликтовать с пользовательскими).

## Composite key (пароль + keyfile)

Рекомендуется в проде:

```bash
manage.py secrets backend set-credentials keepass \
    kdbx_path=/var/lib/postinstall/secrets.kdbx \
    password=... \
    keyfile_path=/etc/postinstall/secrets.key
```

Keyfile генерируется отдельно (например, через 'keepassxc-cli' или
'head -c 128 /dev/urandom > secrets.key').

### Что происходит при записи

- Файловый лок на `<kdbx>.lock.`
- Snapshot текущего `.kdbx` в `<backup_dir>/<stem>.<YYYYmmdd-HHMMSS>.kdbx`.
- Модификация в памяти.
- Сохранение в `<kdbx>.tmp`.
- **fsync**(tmp) + **os.replace**(tmp, kdbx) + **fsync**(директория) — атомарно.
- Ротация старых снапшотов (по backup_retention).

При падении процесса между шагами 4 и 5 исходный файл не тронут.
При падении между 5 и началом работы следующей операции — файл уже
полностью записан.

### Валидация пути

Запрещено размещать .kdbx:

- в `/tmp`;
- в `/proc`, `/sys`, `/dev`;
- внутри `BASE_DIR`, `STATIC_ROOT`, `MEDIA_ROOT` проекта.

Рекомендуемое размещение — `/var/lib/postinstall/secrets.kdbx` с правами
**0600** и владельцем — пользователем, от которого работает приложение.

### Резервное копирование

Снапшоты в `<backup_dir>` — это защита от ошибочной записи, но не
замена бэкапу. Раз в сутки .kdbx нужно копировать на отдельный носитель
или в S3.

Проверка восстановления:

```bash
cp /path/to/backup/secrets.kdbx ./restore.kdbx
keepassxc-cli db-info ./restore.kdbx
```

### Проверка состояния

```bash
manage.py secrets backend test keepass
# {'status': 'ok', 'path': '/var/lib/postinstall/secrets.kdbx',
#  'entries': 42, 'groups': 8, 'keyfile': True}
```

### Management-команды

```bash
# создать пустую базу
manage.py secrets keepass create --path /var/lib/postinstall/secrets.kdbx

# создать с keyfile
manage.py secrets keepass create \
    --path /var/lib/postinstall/secrets.kdbx \
    --keyfile /etc/postinstall/secrets.key

# проверить
manage.py secrets keepass validate
manage.py secrets keepass info

# выгрузить всё из блоба (local) в .kdbx — для миграции
manage.py secrets keepass export --path /var/lib/postinstall/new.kdbx --yes

# загрузить из .kdbx в активный backend
manage.py secrets keepass import --prefix imported/
```