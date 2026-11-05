# Идеи для развития и рефакторинга

## Граф зависимостей (визуал)

**django-dependency-map** — визуализация

**Панель в Django Debug Toolbar**. Показывает граф app-зависимостей, циклы, import-linter violations (если настроен). Только для dev.

**depcycle / dependenpy / dependaman** — CLI

Быстро построить граф:

```bash
depcycle apps/ --format svg --output deps.svg
```

Плюсы: без настройки, PNG/SVG.
Минусы: не проверяет архитектуру, только визуализирует.

## A261 — унифицировать хелперы ролей в тестах

- `_assign` (локальный в test_access_hierarchy.py, matrix, access)
- `add_role` (tests/helpers.py)
Привести к одному. Сделать после того, как все тесты зелёные.

## Audit tamper protection против root-атакующего (A-idea)

Проблема: если атакующий получил root к БД, он может удалить всё:
записи, seal'ы, весь AuditLog. Текущий verify_source детектит только
неконсистентность (chain break, bad seal, seal-gap), но НЕ детектит
полное удаление. Тест test_verify_detects_seal_gap создаёт
искусственный «seal с дыркой», который в реальности не возникает
(атакующий удалит всё, а не оставит дырку) — ложное успокоение.

Удалить test_verify_detects_seal_gap как вводящий в заблуждение.

Направления защиты (обсудить, не реализовывать сейчас):

1. Внешний append-only sink (rsyslog/S3 WORM/Loki) — дублирование
   логов вне БД. Атакующий должен взломать и БД, и sink.
   В audit.py уже есть AUDIT_SYSLOG_ENABLED — реализовать.

2. Merkle tree: каждый seal — лист, корень публикуется
   вне системы (GitHub commit / внешний notary / blockchain).
   verify_source сверяет с опубликованным корнем — детектит
   удаление любой записи.

3. Offline signing key (HSM/KMS) для seal'ов: атакующий не может
   создать валидный seal после удаления. Но не спасает от удаления
   seal'а целиком (только от подделки).

4. Write-only sink в реальном времени (Kafka, Kinesis с retention).
   Атакующий видит только текущее состояние, историю не удалит.

Приоритет: P2 (после A258 secrets, A1 audit fix). Не блокер.

## Внешний audit sink (A-idea, обсудить)

Требование: для prod — обязательный внешний sink для audit-логов
(защита от root-атакующего, который удалит БД).

Конфигурация (через constance или env):

- AUDIT_SINK_REQUIRED: bool (true в prod, false в dev)
- AUDIT_SINK_PROTOCOL: syslog | s3-worm | loki | kafka
- AUDIT_SINK_URL: полный endpoint
- AUDIT_SINK_CREDENTIALS: в secrets (не в БД)

В setup-фазе — обязательный шаг настройки sink (если REQUIRED=true).
Без sink — приложение в prod не стартует (fail-closed).

Не реализовано. P2. Обсудить:

- какой протокол минимум (syslog? S3?)
- куда sink при self-hosted (rsyslog? S3-совместимый?)
- как совместить с существующим AUDIT_SYSLOG_ENABLED
