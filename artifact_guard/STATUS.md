# Artifact Guard - Статус проекта

## ✅ Завершено (Safe MVP - 85%)

### Ядро системы
- [x] Контракты событий (SuspiciousArtifactSubmitted, Indicator, ArtifactAnalysisCompleted)
- [x] Модели домена (ArtifactType, AnalysisContext, AnalysisResult)
- [x] Вердикты (ALLOW, SUSPICIOUS, HIGH_RISK, MANUAL_REVIEW, PROCESSING_ERROR)
- [x] Хеширование и идемпотентность (SHA-256, dedup keys, secure hash)
- [x] PII Redaction (телефоны РФ, email, карты, паспорта, СНИЛС, ИНН)

### Безопасность
- [x] URL Policy с SSRF защитой
  - Блокировка private IP (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Блокировка metadata endpoints (169.254.169.254)
  - Блокировка опасных портов (SSH, Docker, MySQL, PostgreSQL, Redis)
  - DNS resolution с валидацией всех IP
  - Redirect safety checks
- [x] Scoring Engine с probabilistic calculation
- [x] Verdict thresholds (HIGH_RISK≥0.85, SUSPICIOUS≥0.55, MANUAL_REVIEW≥0.30)

### Пайплайн анализа
- [x] AnalysisPipeline с пассивными и активными анализаторами
- [x] 4 пассивных анализатора:
  - DNS Analyzer (подозрительные TLD, fast-flux, отсутствие SPF/DMARC)
  - RDAP Analyzer (новые домены, privacy protection)
  - Homoglyph Analyzer (кириллические/греческие подделки)
  - Reputation Analyzer (блэклисты, IP-репутация)

### Инфраструктура
- [x] Broker (Redis Streams consumer/producer, dead letter queue)
- [x] Ingress layer (extractor, deduplication)
- [x] Storage layer (PostgreSQL с migrations)
- [x] API layer (FastAPI endpoints)
- [x] Адаптер для untilscam_v3

### Тесты
- [x] 164 passing tests
  - Unit тесты: events, hashing, redaction, scoring, url_policy, verdict
  - Integration тесты: pipeline, API

## ⏳ В процессе (10%)

### Анализаторы
- [ ] Web Analyzer (renderer, forms detection, JavaScript analysis)
- [ ] File Analyzer (metadata, archive, YARA, antivirus)
- [ ] Visual Analyzer (OCR, logos, similarity)
- [ ] PII Analyzer (detector, classifier, redactor)

### Evidence Vault
- [ ] Object storage для скриншотов и HTML
- [ ] Шифрование доказательств
- [ ] Manifest для каждого объекта
- [ ] Retention policy

## ❌ Ожидает (5%)

### Renderer
- [ ] Изолированный browser worker (Playwright)
- [ ] Egress proxy с фильтрацией
- [ ] Security hardening контейнера

### Production готовность
- [ ] Calibration на размеченных данных
- [ ] Monitoring false positives
- [ ] Shadow mode перед автоматическими действиями
- [ ] Drift detection

## Структура проекта

```
artifact_guard/
├── shared/           # Конфигурация, события, хеширование, redaction
├── domain/           # Модели домена, артефакты, вердикты
├── analysis/         # Пайплайн и анализаторы
│   ├── passive/      # DNS, RDAP, homoglyphs, reputation
│   └── pipeline.py   # Оркестратор
├── policy/           # URL policy, file policy, PII policy
├── broker/           # Redis Streams consumer/producer
├── ingress/          # Extractor, deduplication
├── storage/          # PostgreSQL, repositories
├── api/              # FastAPI приложение
├── integrations/     # untilscam_v3 адаптер
└── tests/            # 164 passing tests
```

## Метрики

| Компонент | Готовность | Тесты |
|-----------|------------|-------|
| Domain models | 100% | ✅ |
| Events | 100% | ✅ |
| Hashing & Dedup | 100% | ✅ |
| PII Redaction | 100% | ✅ |
| URL Policy (SSRF) | 100% | ✅ |
| Scoring Engine | 100% | ✅ |
| Pipeline | 100% | ✅ |
| Passive Analyzers | 100% | ✅ |
| Broker | 100% | ✅ |
| Storage | 100% | ✅ |
| API | 100% | ✅ |
| Web Analyzer | 0% | ❌ |
| File Analyzer | 0% | ❌ |
| Evidence Vault | 0% | ❌ |
| Renderer | 0% | ❌ |

**Общая готовность Safe MVP: 85%**

## Следующие шаги

1. **Web Analyzer** - безопасный рендеринг страниц
2. **File Analyzer** - анализ файлов и архивов
3. **Evidence Vault** - хранение доказательств
4. **Production calibration** - настройка порогов на реальных данных

Все 164 теста проходят успешно! 🎉
