from __future__ import annotations

import base64
import getpass
import secrets as _secrets
import sys

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.secrets import blob as blob_mod
from apps.secrets.models import SecretAccessLog, ServerKey, log_action
from apps.secrets.runtime import SecretsSealed, runtime


def _require_tty() -> None:
    if not sys.stdin.isatty():
        raise CommandError("команда требует интерактивного терминала")


def _ask_master_key(prompt: str = "Мастер-ключ: ") -> str:
    key = getpass.getpass(prompt)
    if not key:
        raise CommandError("пустой ввод")
    return key


class Command(BaseCommand):
    help = "Управление секретами (init / status / unlock / rotate / reset)"

    def add_arguments(self, parser):
        # Первичная инициализация
        sub = parser.add_subparsers(dest="cmd", required=True)

        sub.add_parser("init", help="Первичная инициализация")
        sub.add_parser("status", help="Текущее состояние")
        sub.add_parser("unlock", help="Разблокировать текущий процесс")
        sub.add_parser("seal", help="Заблокировать текущий процесс")
        sub.add_parser("rotate", help="Сменить мастер-ключ")
        
        # Удалить локальный блоб
        reset = sub.add_parser("reset", help="Удалить блоб (ОПАСНО)")
        reset.add_argument("--i-know-what-i-am-doing", action="store_true")

        # Управление бэкендом (Поддерживаются: локальный блоб, openbao, keepass)
        backend = sub.add_parser("backend", help="Управление backend")
        backend.add_argument("action", nargs="?", default="list",
                             choices=["list", "set", "test", "credentials",
                                      "set-credentials", "clear-credentials"])
        backend.add_argument("name", nargs="?", default="")
        backend.add_argument("values", nargs="*", default=[])

        # Управление keepass
        kp = sub.add_parser("keepass", help="Работа с .kdbx напрямую")
        kp_sub = kp.add_subparsers(dest="kp_action", required=True)

        kp_create = kp_sub.add_parser("create", help="Создать пустую .kdbx")
        kp_create.add_argument("--path", required=True)
        kp_create.add_argument("--keyfile", default="")

        kp_sub.add_parser("validate", help="Проверить .kdbx из credentials")

        kp_sub.add_parser("info", help="Информация о .kdbx")

        # Экспорт из блоба в keepass
        kp_export = kp_sub.add_parser("export",
                                      help="Экспорт всех секретов из блоба в .kdbx")
        kp_export.add_argument("--path", required=True,
                               help="Куда писать (будет создан или перезаписан)")
        kp_export.add_argument("--keyfile", default="")
        kp_export.add_argument("--yes", action="store_true",
                               help="Перезаписать существующий .kdbx")
        
        # Импорт из keepass в локальный блоб
        kp_import = kp_sub.add_parser("import",
                                      help="Импорт из .kdbx в активный backend")
        kp_import.add_argument("--prefix", default="imported/")

        # Миграции
        mig = sub.add_parser("migrate", help="Миграция секретов между backend'ами")
        mig.add_argument("--from", dest="source", required=False, default="",
                         help="Источник (local | openbao | keepass)")
        mig.add_argument("--to", dest="target", required=False, default="",
                         help="Цель")
        mig.add_argument("--prefix", default="",
                         help="Только записи с этим префиксом path")
        mig.add_argument("--overwrite", action="store_true",
                         help="Перезаписывать существующие в target")
        mig.add_argument("--dry-run", action="store_true",
                         help="Только показать, что будет сделано")
        mig.add_argument("--activate", dest="activate", action="store_true",
                         default=False,
                         help="Переключить активный backend на target после успеха")
        mig.add_argument("--no-activate", dest="activate", action="store_false",
                         help="Не переключать (по умолчанию)")
        mig.add_argument("--resume", default="", help="UUID миграции для продолжения")
        mig.add_argument("--list", dest="list_migrations", action="store_true",
                         help="Показать историю миграций")
        mig.add_argument("--status", default="", help="UUID для показа статуса")

    def handle(self, *args, **opts):
        cmd = opts["cmd"]
        method = getattr(self, f"_cmd_{cmd}", None)
        if not method:
            raise CommandError(f"неизвестная команда: {cmd}")
        method(**opts)

        if cmd == "backend":
            self._cmd_backend(**opts)
            return

        if cmd == "keepass":
            self._cmd_keepass(**opts)
            return

    # --- init ---

    def _cmd_init(self, **_):
        _require_tty()
        if ServerKey.objects.exists():
            raise CommandError(
                "ServerKey уже существует. Для смены ключа — secrets rotate."
            )

        self.stdout.write(
            "Сейчас будет создан зашифрованный блоб.\n"
            "Мастер-ключ НЕ сохраняется на сервере — только зашифрованный блоб.\n"
            "Потеря мастер-ключа = безвозвратная потеря всех секретов.\n"
        )
        confirm = input('Напишите "I understand" для продолжения: ').strip()
        if confirm != "I understand":
            raise CommandError("отменено")

        key1 = _ask_master_key("Новый мастер-ключ: ")
        key2 = _ask_master_key("Повторите: ")
        if key1 != key2:
            raise CommandError("мастер-ключи не совпадают")

        salt = blob_mod.new_salt()
        kek = blob_mod.derive_kek(key1, salt)
        blob = blob_mod.encrypt_blob(blob_mod.empty_blob(), kek)

        ServerKey.objects.create(
            salt=base64.b64encode(salt).decode(),
            blob=base64.b64encode(blob).decode(),
        )
        log_action(SecretAccessLog.Action.INIT, success=True)

        self.stdout.write(self.style.SUCCESS("Готово. ServerKey создан."))
        self.stdout.write("")
        self.stdout.write("Сохраните мастер-ключ в двух местах. Он больше нигде не хранится.")
        self.stdout.write("")
        self.stdout.write("Для автозагрузки создайте файл 0600 и укажите:")
        self.stdout.write("  SECRETS_MASTER_KEY_FILE=/path/to/master.key")

    # --- status ---

    def _cmd_status(self, **_):
        s = runtime.status()
        self.stdout.write(f"state:          {s.state}")
        self.stdout.write(f"pid:            {s.pid}")
        if s.state == "unsealed":
            self.stdout.write(f"version:        {s.version}")
            self.stdout.write(f"active_backend: {s.active_backend}")
            self.stdout.write(f"secrets:        {s.secrets_count}")

    # --- unlock / seal ---

    def _cmd_unlock(self, **_):
        _require_tty()
        key = _ask_master_key()
        try:
            runtime.unlock(key)
        except SecretsSealed as exc:
            log_action(SecretAccessLog.Action.UNLOCK, success=False, error=str(exc))
            raise CommandError(f"не удалось: {exc}")  # noqa: B904
        log_action(SecretAccessLog.Action.UNLOCK, success=True)
        self.stdout.write(self.style.SUCCESS("Разблокировано."))

    def _cmd_seal(self, **_):
        runtime.seal()
        log_action(SecretAccessLog.Action.SEAL, success=True)
        self.stdout.write(self.style.SUCCESS("Заблокировано."))

    # --- rotate ---

    def _cmd_rotate(self, **_):
        _require_tty()
        self.stdout.write("Смена мастер-ключа. Все секреты будут перешифрованы.")
        old = _ask_master_key("Текущий мастер-ключ: ")
        new1 = _ask_master_key("Новый мастер-ключ: ")
        new2 = _ask_master_key("Повторите: ")
        if new1 != new2:
            raise CommandError("новые мастер-ключи не совпадают")
        try:
            runtime.rotate_master_key(old, new1)
        except SecretsSealed as exc:
            log_action(SecretAccessLog.Action.ROTATE, success=False, error=str(exc))
            raise CommandError(f"не удалось: {exc}")  # noqa: B904
        log_action(SecretAccessLog.Action.ROTATE, success=True)
        self.stdout.write(self.style.SUCCESS("Мастер-ключ сменён."))
        self.stdout.write("Обновите SECRETS_MASTER_KEY_FILE на всех инстансах.")

    # --- reset ---

    def _cmd_reset(self, i_know_what_i_am_doing=False, **_):
        _require_tty()
        if not i_know_what_i_am_doing:
            raise CommandError(
                "Операция удаляет ServerKey и все секреты безвозвратно.\n"
                "Если действительно нужно — добавьте --i-know-what-i-am-doing."
            )
        if not ServerKey.objects.exists():
            self.stdout.write("ServerKey не существует.")
            return

        self.stdout.write(
            self.style.WARNING(
                "Вы собираетесь удалить ServerKey. Все секреты будут потеряны.\n"
                "Восстановление невозможно."
            )
        )
        if input('Напишите "delete all secrets": ').strip() != "delete all secrets":
            raise CommandError("отменено")
        key = _ask_master_key("Мастер-ключ для подтверждения: ")
        try:
            runtime.unlock(key)
        except SecretsSealed:
            raise CommandError("мастер-ключ неверный")  # noqa: B904

        ServerKey.objects.all().delete()
        runtime.seal()
        log_action(SecretAccessLog.Action.RESET, success=True)
        self.stdout.write(self.style.SUCCESS("ServerKey удалён."))


    def _cmd_backend(self, action: str | None = None, name: str = "",
                    values: list[str] | None = None, **_) -> None:
        """Управление backend и credentials.

        secrets backend                      — список
        secrets backend list                 — то же
        secrets backend set <name>           — переключить активный
        secrets backend credentials <name>   — показать (маскированно)
        secrets backend set-credentials <name> k=v [k=v ...]   — записать
        secrets backend clear-credentials <name>
        secrets backend test <name>          — health-check
        """
        from apps.secrets.services import (
            delete_backend_credentials,
            get_backend_credentials,
            list_backends,
            set_active_backend,
            set_backend_credentials,
            test_backend,
        )

        action = action or "list"

        if action == "list":
            rows = list_backends()
            self.stdout.write(f"{'NAME':<10} {'ACTIVE':<7} {'CREDS':<6} {'HEALTH':<10}")
            for r in rows:
                health = r.health.get("status", "—")
                self.stdout.write(
                    f"{r.name:<10} "
                    f"{'yes' if r.active else '':<7} "
                    f"{'yes' if r.credentials_set else 'no':<6} "
                    f"{health:<10}"
                )
            return

        if action == "set":
            if not name:
                raise CommandError("укажите имя backend: secrets backend set <name>")
            ok = set_active_backend(name)
            if ok:
                self.stdout.write(self.style.SUCCESS(f"active backend: {name}"))
            else:
                raise CommandError(
                    f"не удалось переключить на {name} (health-check не прошёл)"
                )
            return

        if action == "test":
            if not name:
                raise CommandError("укажите имя backend")
            result = test_backend(name)
            self.stdout.write(f"{name}: {result}")
            return

        if action == "credentials":
            if not name:
                raise CommandError("укажите имя backend")
            creds = get_backend_credentials(name)
            if not creds:
                self.stdout.write(f"{name}: credentials не заданы")
                return
            for k, v in sorted(creds.items()):
                masked = self._mask(v) if self._is_secret_key(k) else v
                self.stdout.write(f"  {k} = {masked}")
            return

        if action == "set-credentials":
            if not name:
                raise CommandError("укажите имя backend")
            if not values:
                raise CommandError("передайте пары key=value")
            parsed: dict[str, str] = {}
            for item in values:
                if "=" not in item:
                    raise CommandError(f"неверный формат: {item!r}, ожидалось k=v")
                k, v = item.split("=", 1)
                parsed[k.strip()] = v
            set_backend_credentials(name, parsed)
            self.stdout.write(self.style.SUCCESS(
                f"{name}: записаны ключи {sorted(parsed.keys())}"
            ))
            return

        if action == "clear-credentials":
            if not name:
                raise CommandError("укажите имя backend")
            if input(f'Очистить credentials для {name}? [y/N] ').lower() != "y":
                raise CommandError("отменено")
            delete_backend_credentials(name)
            self.stdout.write(self.style.SUCCESS(f"{name}: credentials очищены"))
            return

        raise CommandError(f"неизвестное действие: {action}")

    def _cmd_keepass(self, kp_action: str, **opts) -> None:
        from pathlib import Path

        from apps.secrets.backends.keepass import KeepassBackend
        from apps.secrets.keepass_helpers import (
            KeepassError,
            KeepassParams,
            get_cached,
            validate_path,
        )
        from apps.secrets.services import get_backend, list_paths, runtime

        if kp_action == "create":
            self._keepass_create(Path(opts["path"]), opts.get("keyfile") or "")
            return
        if kp_action == "validate":
            self._keepass_validate()
            return
        if kp_action == "info":
            self._keepass_info()
            return
        if kp_action == "export":
            self._keepass_export(Path(opts["path"]),
                                opts.get("keyfile") or "",
                                overwrite=opts.get("yes", False))
            return
        if kp_action == "import":
            self._keepass_import(prefix=opts.get("prefix") or "imported/")
            return
        raise CommandError(f"неизвестное действие keepass: {kp_action}")

    def _cmd_migrate(
        self, *,
        source="", target="", prefix="", overwrite=False, dry_run=False,
        activate=False, resume="", list_migrations=False, status="", **_
    ):
        from apps.secrets.migration import (
            get_migration,
            migrate,
        )
        from apps.secrets.migration import (
            list_migrations as _list,
        )
        from apps.secrets.models import SecretsMigration

        if list_migrations:
            rows = _list(limit=50)
            if not rows:
                self.stdout.write("История миграций пуста.")
                return
            self.stdout.write(
                f"{'ID':<38} {'FROM':<9} {'TO':<9} "
                f"{'STATUS':<10} {'DONE':<6} {'SKIP':<6} {'FAIL':<6} STARTED"
            )
            for m in rows:
                self.stdout.write(
                    f"{str(m.id):<38} {m.source_backend:<9} {m.target_backend:<9} "
                    f"{m.status:<10} {m.done:<6} {m.skipped:<6} {m.failed:<6} "
                    f"{m.started_at:%Y-%m-%d %H:%M}"
                )
            return

        if status:
            try:
                m = get_migration(status)
            except Exception:
                raise CommandError(f"миграция {status} не найдена")  # noqa: B904
            
            self.stdout.write(f"id:        {m.id}")
            self.stdout.write(f"from → to: {m.source_backend} → {m.target_backend}")
            self.stdout.write(f"status:    {m.status}")
            self.stdout.write(f"progress:  {m.done + m.skipped + m.failed}/{m.total} "
                            f"({m.progress_pct}%)")
            self.stdout.write(f"  done:    {m.done}")
            self.stdout.write(f"  skipped: {m.skipped}")
            self.stdout.write(f"  failed:  {m.failed}")
            if m.last_path:
                self.stdout.write(f"last:      {m.last_path}:{m.last_key}")
            if m.error:
                self.stdout.write(self.style.ERROR(f"error: {m.error}"))
            if m.details:
                self.stdout.write("details (последние):")
                for d in m.details[-5:]:
                    self.stdout.write(f"  [{d['kind']}] {d['path']}:{d['key']} "
                                    f"{d.get('message','')}")
            return

        # --- запуск миграции ---
        if not resume and (not source or not target):
            raise CommandError("укажите --from и --to (или --resume <id>)")

        if resume:
            # проверим, что есть
            try:
                existing = get_migration(resume)
            except Exception:
                raise CommandError(f"миграция {resume} не найдена")  # noqa: B904
            
            source = source or existing.source_backend
            target = target or existing.target_backend

        def _progress(p):
            self.stdout.write(
                f"\r  [{p.processed}/{p.total}] done={p.done} "
                f"skip={p.skipped} fail={p.failed} — {p.current_path[:60]}",
                ending="",
            )
            self.stdout.flush()

        try:
            m = migrate(
                source=source, target=target,
                prefix=prefix, overwrite=overwrite, dry_run=dry_run,
                activate_target=activate,
                resume_id=resume or None,
                progress_cb=_progress,
            )
        except Exception as exc:
            raise CommandError(f"миграция не удалась: {exc}")  # noqa: B904

        self.stdout.write("")  # перевод строки после \r
        self.stdout.write("")
        self.stdout.write(f"id:        {m.id}")
        self.stdout.write(f"status:    {m.status}")
        self.stdout.write(f"total:     {m.total}")
        self.stdout.write(f"  done:    {m.done}")
        self.stdout.write(f"  skipped: {m.skipped}")
        self.stdout.write(f"  failed:  {m.failed}")
        if m.error:
            self.stdout.write(self.style.ERROR(f"error: {m.error}"))

        if m.status == SecretsMigration.Status.CANCELLED:
            self.stdout.write(
                self.style.WARNING(
                    f"\nПрервано. Продолжить: manage.py secrets migrate --resume {m.id}"
                )
            )
    
    def _keepass_create(self, path, keyfile_str: str) -> None:
        """Создать пустой .kdbx."""
        import getpass
        from pathlib import Path

        from pykeepass import create_database

        from apps.secrets.keepass_helpers import validate_path

        if path.exists():
            raise CommandError(f"{path} уже существует")

        keyfile = Path(keyfile_str).expanduser().resolve() if keyfile_str else None
        if keyfile and not keyfile.exists():
            raise CommandError(f"keyfile не существует: {keyfile}")

        # проверим путь через тот же валидатор
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            validate_path(path, allow_missing=True)
        except Exception as exc:
            raise CommandError(str(exc))  # noqa: B904

        password = getpass.getpass("Мастер-пароль для .kdbx: ")
        if not password:
            raise CommandError("пустой пароль")
        p2 = getpass.getpass("Повторите: ")
        if password != p2:
            raise CommandError("пароли не совпадают")

        try:
            create_database(str(path), password=password,
                            keyfile=str(keyfile) if keyfile else None)
        except Exception as exc:
            raise CommandError(f"не удалось создать .kdbx: {exc}")  # noqa: B904

        try:
            path.chmod(0o600)
        except OSError:
            pass

        self.stdout.write(self.style.SUCCESS(f"Создан {path}"))
        self.stdout.write("")
        self.stdout.write("Скопируйте пароль в credentials backend'а:")
        self.stdout.write(
            f"  manage.py secrets backend set-credentials keepass "
            f"kdbx_path={path} password=..."
            + (f" keyfile_path={keyfile}" if keyfile else "")
        )

    def _keepass_validate(self) -> None:
        from apps.secrets.backends.keepass import KeepassBackend
        try:
            b = KeepassBackend()
        except Exception as exc:
            raise CommandError(f"не удалось инициализировать: {exc}")  # noqa: B904
        
        h = b.health()
        self.stdout.write(f"{h}")
        if h.get("status") != "ok":
            raise CommandError("keepass health != ok")

    def _keepass_info(self) -> None:
        from apps.secrets.backends.keepass import KeepassBackend
        b = KeepassBackend()
        kp = b._load() if hasattr(b, "_load") else None
        from apps.secrets.keepass_helpers import get_cached
        kp = get_cached(b.params)
        self.stdout.write(f"path:      {b.params.kdbx_path}")
        self.stdout.write(f"keyfile:   {b.params.keyfile_path or '—'}")
        self.stdout.write(f"groups:    {len(kp.groups)}")
        self.stdout.write(f"entries:   {len(kp.entries)}")
        self.stdout.write(f"backups:   {b.params.effective_backup_dir}")

    def _keepass_export(self, path, keyfile_str: str, *, overwrite: bool) -> None:
        """Выгрузить все секреты из блоба в .kdbx."""
        import getpass
        from pathlib import Path

        from apps.secrets.keepass_helpers import (
            KeepassParams,
        )
        from apps.secrets.runtime import runtime

        if path.exists() and not overwrite:
            raise CommandError(f"{path} существует. Используйте --yes.")

        if not runtime.is_unsealed():
            raise CommandError("runtime sealed — сначала unlock")

        password = getpass.getpass("Мастер-пароль для нового .kdbx: ")
        if not password:
            raise CommandError("пустой пароль")
        p2 = getpass.getpass("Повторите: ")
        if password != p2:
            raise CommandError("пароли не совпадают")

        keyfile = Path(keyfile_str).expanduser().resolve() if keyfile_str else None

        from pykeepass import create_database
        
        try:
            create_database(str(path), password=password,
                            keyfile=str(keyfile) if keyfile else None)
        except Exception as exc:
            raise CommandError(f"не удалось создать: {exc}")  # noqa: B904

        params = KeepassParams(
            kdbx_path=path, password=password,
            keyfile_path=keyfile, backup_retention=0,
        )
        from apps.secrets.backends.keepass import KeepassBackend
        backend = KeepassBackend.__new__(KeepassBackend)
        backend.params = params

        # используем существующий API set
        count = 0
        for path_str in runtime.list_paths():
            # читаем всё, что есть
            try:
                data = runtime._data["secrets"]
                node = data
                for part in path_str.split("/"):
                    node = node[part]
                for k, v in node.items():
                    backend.set(path_str, k, str(v))
                    count += 1
            except Exception as exc:
                self.stderr.write(f"skip {path_str}: {exc}")
        self.stdout.write(self.style.SUCCESS(f"экспортировано полей: {count}"))

    def _keepass_import(self, *, prefix: str) -> None:
        """Импорт из .kdbx в активный backend (обычно local)."""
        from apps.secrets.backends.keepass import CUSTOM_PREFIX, KeepassBackend
        from apps.secrets.keepass_helpers import get_cached
        from apps.secrets.services import set_secret

        b = KeepassBackend()
        kp = get_cached(b.params)

        def walk(group, path_parts: list[str]) -> int:
            n = 0
            for entry in group.entries:
                entry_path = "/".join(path_parts + [entry.title])
                if entry.password:
                    set_secret(prefix + entry_path, "password", entry.password)
                    n += 1
                if entry.username:
                    set_secret(prefix + entry_path, "username", entry.username)
                    n += 1
                if entry.url:
                    set_secret(prefix + entry_path, "url", entry.url)
                    n += 1
                if entry.notes:
                    set_secret(prefix + entry_path, "notes", entry.notes)
                    n += 1
                for cp in entry.custom_properties:
                    if cp.startswith(CUSTOM_PREFIX):
                        key = cp[len(CUSTOM_PREFIX):]
                        set_secret(
                            prefix + entry_path, key,
                            str(entry.get_custom_property(cp)),
                        )
                        n += 1
            for sg in group.subgroups:
                n += walk(sg, path_parts + [sg.name])
            return n

        total = walk(kp.root_group, [])
        self.stdout.write(self.style.SUCCESS(f"импортировано полей: {total}"))

    @staticmethod
    def _mask(value: str) -> str:
        if len(value) <= 8:
            return "***"
        return f"{value[:4]}…{value[-4:]}"

    @staticmethod
    def _is_secret_key(key: str) -> bool:
        return any(s in key.lower() for s in ("token", "password", "secret", "key"))