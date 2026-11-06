# Paylater Monitor (Go)

Единая панель мониторинга инфраструктуры Paylater — порт с C# на Go.

## Возможности

- **Серверы (ServerCore / Nova API)** — список ВМ, метрики CPU/RAM/Disk, IAM-токен (Keystone)
- **Docker-контейнеры** — `docker ps`, `docker stats`, start/stop/restart, логи (SSH)
- **Graylog** — состояние кластера, ноды, streams, поиск логов (PROD/TEST)
- **Zeebe (Camunda 8)** — метрики через Prometheus (SSH-туннель), процессы/инциденты через Operate API
- **MS Teams** — Adaptive Cards, алерты, часовые отчёты
- **Vault** — каталог секретов KV v1/v2, чтение/запись, эфемерные ключи
- **AI-диагностика** — автообнаружение проблем, диагноз через ChatGPT/OpenAI или Koda CLI
- **Управление ВМ** — создание, удаление, start/stop/restart, консоль, пароли (RSA)
- **TLS-аудит** — страница `/tls`: **комплексная** проверка TLS/HTTP-конфигурации:
  - все версии TLS (1.0–1.3) и cipher suites на **каждом** обнаруженном порту (для Linux — полный список слушающих портов через `ss`/`netstat` + опубликованные порты Docker + расширенный `DefaultPorts`);
  - протокол на порту по реальному ответу: `https`/`tls`/`http`/`tcp`/`closed` (GET-запрос);
  - анализ **nginx**: установлен/запущен, `ssl_protocols`, `listen ... ssl`, проблемы;
  - анализ **Docker**: проброшенные порты контейнеров;
  - слабые cipher suites (RC4/3DES/CBC-SHA1) на каждом порту;
  - ОС определяется **без SSH** для Windows/MikroTik (по образу ОС из Nova), SSH к Windows не выполняется;
  - рекомендации и **экспорт отчёта в PDF** (jsPDF + autotable, шрифт DejaVu Sans с кириллицей, файлы — локально в `static/`, CDN не нужен). Проверка запускается **асинхронно** — страница открывается мгновенно, в браузере идут часы и прогресс, результаты кэшируются на 10 минут. Если SSH-пароль недоступен — генерируется новый через Nova `changePassword`
- **Staging-TLS** — страница `/staging-tls`: проверка готовности PROD к TLS 1.3. PROD-серверы берутся напрямую из списка ServerCore (по имени «prod»), сканируются на TLS/HTTP/nginx/Docker, собираются версии ПО (OS/Kernel/Docker/Nginx/OpenSSL/Java/Node), нагрузочный TLS 1.3 тест, отчёт о проблемах (критические / с обходными путями / рекомендации) и вердикт готовности PROD к TLS 1.3. Проверка **асинхронная**: страница открывается сразу, в браузере часы + прогресс, результаты кэшируются 10 минут. Многоуровневая защита от зависания: общий таймаут 5 мин, per-server таймаут 90с (всегда), per-port таймаут 15с, SSH-соединение/команды/HTTP-вызовы к Nova — все уважают context cancellation
- **Статистика серверов** — реальные метрики CPU/RAM/Disk собираются по SSH (параллельно, TTL-кэш 60с), а не берутся из metadata Nova (раньше показывались 0.0); CPU-парсер устойчив к разным версиям `top` (поле `idle` по имени, fallback на `/proc/stat`)
- **Логи приложения** — страница `/logs`: просмотр лог-файла `logs/app.log` с автообновлением
- **Графический редактор конфигурации** — страница `/system`: форма вместо YAML-редактора, изменения сохраняются и применяются без перезапуска
- **Фоновый мониторинг** — каждые 5 минут проверка контейнеров/серверов/Graylog/Zeebe, немедленные алерты с dedup, часовой сводный отчёт
- **Таймаут SSH-команд** — каждая команда (`docker ps`, `docker stats`, метрики CPU/RAM/Disk) выполняется с таймаутом 30с; при отсутствии ответа от сервера команда прерывается и цикл мониторинга переходит к следующему серверу, не зависая

## Архитектура

```
panel-go/
├── cmd/server/main.go          — точка входа
├── internal/
│   ├── config/                 — YAML-конфигурация, Store
│   ├── models/                 — общие модели данных
│   ├── sshclient/              — SSH-клиент (golang.org/x/crypto/ssh)
│   ├── servercore/             — IAM-токен, Nova API, Docker, ВМ, пароли
│   ├── graylog/                — Graylog REST API
│   ├── zeebe/                  — Prometheus (SSH-туннель) + Operate API
│   ├── msteams/                — Adaptive Cards в MS Teams
│   ├── vault/                  — HashiCorp Vault (KV v1/v2, эфемерные)
│   ├── aidiag/                 — ИИ-диагностика + детектор проблем
│   ├── tlsscan/                — TLS-аудит серверов (пункт 29 IMPROVEMENTS.md)
│   ├── monitor/                — фоновый мониторинг и алерты
│   └── web/                    — HTTP-слой (net/http + html/template)
├── static/                     — CSS, JS
├── config.yaml                 — конфигурация (заполнить перед запуском)
└── deploy.ps1                  — скрипт деплоя (Windows)
```

> **Шаблоны:** каждая страница рендерится из собственного набора шаблонов
> (`layout` + свой `content`). Базовый `layout.html` клонируется под каждую
> страницу в `loadTemplates()`, поэтому блоки `{{define "content"}}`
> не коллидируют между собой (см. `internal/web/templates.go`).

## Технологии

| Компонент | Выбор |
|-----------|-------|
| Язык | Go 1.26 |
| HTTP | `net/http` (стандартная библиотека) |
| Шаблоны | `html/template` (layout клонируется под каждую страницу) |
| SSH | `golang.org/x/crypto/ssh` |
| Конфиг | YAML (`gopkg.in/yaml.v3`) |
| Деплой | Windows |

## Быстрый старт

```powershell
# 1. Заполнить config.yaml (IAM-пароль, Graylog, Teams webhook и т.д.)
# 2. Собрать
go build -o paylater-mon.exe ./cmd/server

# 3. Запустить
.\paylater-mon.exe -config config.yaml
```

Панель доступна по адресу `http://localhost:9090`.

## Деплой

Деплой на production-сервер `172.31.32.23` по SSH (plink/pscp):

```powershell
.\deploy.ps1
```

Скрипт выполняет:
1. Сборку `paylater-mon.exe`
2. Упаковку артефактов (exe + config.yaml + static + templates) в ZIP
3. Копирование ZIP на сервер через SCP
4. Удалённо через SSH:
   - Остановка службы `PaylaterMonitor` (если существует)
   - Удаление службы (если существует)
   - Распаковка в `C:\paylater-mon` (config.yaml сохраняется)
   - Проверка/установка NSSM (Non-Sucking Service Manager)
   - Создание службы `PaylaterMonitor` через NSSM с auto-start
   - Настройка: рабочая директория, параметры, ротация логов
   - Запуск службы
5. Проверка статуса службы

Служба настроена на **автоматический запуск** при старте сервера (`SERVICE_AUTO_START`).

Логи службы: `C:\paylater-mon\logs\stdout.log` и `stderr.log` (ротация 10 MB).

### Требования для деплоя

- PuTTY (`plink.exe`, `pscp.exe`) — в `C:\plink\` или в PATH
- Go 1.26+ для сборки
- SSH-доступ к `172.31.32.23` (пользователь `programm`)

## Конфигурация

Все настройки перенесены из `settings.bin` (C# панель) в `config.yaml` (YAML).
Основные секции:

- `servercore` — IAM-учётные данные, SSH, **excluded_servers** (выведенные из эксплуатации ВМ — по имени или IP), **server_groups** (группировка серверов по имени: Mikrotik/Администрация/Мобилка/Тестовые/Боевые; группы с `monitored: false` не опрашиваются по SSH). Списки редактируются через графический редактор в «Система» или через API `/api/servercore/decommissioned` (POST: `add`/`remove`) без перезагрузки. При выводе/вводе сервера отправляется однократное оповещение в MS Teams. SSH-аутентификация: password + keyboard-interactive + public key (если настроен `ssh_private_key_path`)
- `graylog` — URL/учётные данные PROD/TEST
- `zeebe` — URL, SSH-туннель (SSH-сервер определяется по IP из `prod_url`/`test_url`, например 172.31.32.69 → `uz-prod-camunda87-1`, или явным `server_name`)
- `msteams` — webhook URL
- `vault` — адрес, токен, пути KV
- `ai_diagnostics` — ChatGPT API key / Koda CLI path
- `staging_tls` — настройки Staging-TLS: `servers` (явный список staging-серверов), `max_prod_scan` (лимит PROD для сравнения), `scan_concurrency` (параллельных сканов, по умолчанию 4), `load_test_*` (параметры нагрузочного теста TLS 1.3)

> **Аутентификация:** все страницы требуют session-based auth (или basic-auth).
> Публичные пути без auth: `/login`, `/logout`, `/health`, `/metrics`, `/static/*`
> (CSS/JS доступны до входа, иначе браузер не получит стили для login-страницы).

## Автор

Mikhail Gubin, DevOps
