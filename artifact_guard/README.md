# Artifact Guard

Безопасный анализатор ссылок, доменов, файлов и потенциальных утечек персональных данных.

## Архитектура

```
untilscam_v3
    ↓ SuspiciousArtifactSubmitted
Artifact Guard
    ├── нормализация и дедупликация
    ├── пассивная проверка домена/URL (DNS, RDAP, TLS, reputation)
    ├── безопасное открытие страницы в sandbox (renderer)
    ├── анализ файлов (ClamAV, YARA, metadata)
    ├── OCR и визуальное сравнение
    ├── поиск признаков фишинга/скама
    ├── обнаружение и редактирование PII
    └── итоговый отчёт + доказательства
```

## Вердикты

- **ALLOW** (risk < 0.30) — артефакт безопасен
- **SUSPICIOUS** (0.55 ≤ risk < 0.85) — требуется предупреждение
- **HIGH_RISK** (risk ≥ 0.85) — срочный alert, возможна блокировка
- **MANUAL_REVIEW** (0.30 ≤ risk < 0.55) — ручная проверка аналитиком
- **PROCESSING_ERROR** — ошибка анализа

## Структура проекта

```
artifact_guard/
├── shared/           # Общие утилиты (events, hashing, redaction, logging)
├── domain/           # Доменные модели (artifact, analysis, verdict, evidence)
├── ingress/          # Приём артефактов (consumer, extractor, deduplication)
├── broker/           # Redis Streams producer/consumer, dead letter
├── policy/           # Политики безопасности (URL, SSRF, file, PII)
├── analysis/         # Пайплайн анализа
│   ├── passive/      # DNS, RDAP, TLS, reputation, homoglyphs
│   ├── web/          # Browser renderer, redirects, forms, screenshots
│   ├── files/        # Metadata, archive, YARA, antivirus
│   ├── visual/       # OCR, logos, similarity
│   └── pii/          # Detector, classifier, redactor
├── renderer/         # Изолированный browser worker (Playwright)
├── scoring/          # Scoring engine, rules, calibration
├── evidence/         # Evidence vault, manifest, encryption
├── storage/          # PostgreSQL, object store, repositories
├── api/              # FastAPI endpoints
├── integrations/     # Адаптеры для untilscam_v3
└── tests/            # Unit, integration, security тесты
```

## Быстрый старт

### Требования

- Python 3.12+
- Redis 7+
- PostgreSQL 15+
- Docker & Docker Compose

### Установка

```bash
pip install -e .
```

### Запуск тестов

```bash
pytest tests/ -v
```

### Локальный запуск (dev)

```bash
docker-compose up -d redis postgres
python -m uvicorn api.app:app --reload
```

## Интеграция с untilscam_v3

```python
from integrations.untilscam_adapter import ArtifactGuardPublisher

publisher = ArtifactGuardPublisher(producer=redis_producer)

# Отправка URL на анализ
event_id = await publisher.submit_url(
    correlation_id=correlation_id,
    url="https://suspicious-site.com/login",
    chat_id=123456789,
    message_id=999,
    context_excerpt="Click here to win!",
)

# Получение результата через Redis Stream "artifact.completed"
```

## Контракты событий

### SuspiciousArtifactSubmitted (вход)

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "correlation_id": "uuid",
  "artifact_type": "url|domain|file|text",
  "value": "...",
  "source_system": "untilscam",
  "source_chat_hash": "...",
  "source_message_hash": "...",
  "context_excerpt": "..."
}
```

### ArtifactAnalysisCompleted (выход)

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "correlation_id": "uuid",
  "analysis_id": "uuid",
  "verdict": "ALLOW|SUSPICIOUS|HIGH_RISK|MANUAL_REVIEW",
  "risk_score": 0.85,
  "indicators": [
    {
      "name": "credential_form",
      "score": 0.35,
      "severity": "high",
      "explanation": "Form detected requesting credentials",
      "evidence_ids": ["uuid"]
    }
  ]
}
```

## Безопасность

### SSRF Protection

- Блокировка private IP (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Блокировка metadata endpoints (169.254.169.254)
- Блокировка опасных портов (SSH, Docker, MySQL, PostgreSQL, Redis)
- Egress proxy с фильтрацией CIDR
- Повторная проверка каждого redirect

### Изоляция renderer

- Rootless контейнер
- Drop ALL capabilities
- Read-only filesystem
- tmpfs с noexec,nosuid,nodev
- PID/memory/CPU лимиты
- Отсутствие доступа к внутренней сети
- Один короткоживущий процесс на задание

### PII Redaction

- Телефоны РФ: `+7 *** ***-**-67`
- Email: `u***@example.com`
- Кредитные карты, паспорта, СНИЛС, ИНН
- Контекстный анализ (самопубликация vs доксинг)

### Evidence Vault

- Шифрование объектов отдельным ключом
- Короткоживущие signed URL
- Audit log каждого просмотра
- Автоматическое удаление по retention
- Раздельное хранение оригинала и redacted копии

## Этапы реализации

### Этап 1 — Safe MVP ✅

- [x] Контракты событий
- [x] Нормализация и дедупликация URL
- [x] DNS, RDAP, TLS, redirect-анализ (частично)
- [x] Детерминированный scoring
- [x] PostgreSQL и dead-letter queue
- [x] Результат обратно в untilscam_v3

### Этап 2 — Isolated Web Renderer

- [ ] Одноразовые Playwright workers
- [ ] Egress proxy
- [ ] SSRF-фильтрация каждого запроса
- [ ] Screenshot, DOM и формы
- [ ] Жёсткие CPU/RAM/time limits

### Этап 3 — Files & PII

- [ ] Object storage
- [ ] ClamAV/YARA
- [ ] Безопасный анализ архивов
- [ ] PII detection/redaction
- [ ] Evidence Vault
- [ ] Политика retention

### Этап 4 — Quality

- [ ] Размеченный датасет
- [ ] Precision/recall метрики
- [ ] Мониторинг false positives
- [ ] Shadow mode
- [ ] Drift detection

## Лицензия

MIT
