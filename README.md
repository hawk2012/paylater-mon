# Paylater Monitor

Единая панель мониторинга инфраструктуры Paylater — серверы, Docker-контейнеры, Camunda 8 (Zeebe), Graylog, Vault, MS Teams, AI-диагностика.

## Технологический стек

| Компонент | Технология |
|-----------|------------|
| Язык | Go 1.26 |
| HTTP | `net/http` (стандартная библиотека) |
| Шаблоны | `html/template` (server-rendered) |
| SSH | `golang.org/x/crypto/ssh` |
| Конфигурация | YAML (`gopkg.in/yaml.v3`) |
| Деплой | Windows (NSSM-служба, auto-start) |

## Структура проекта

```
panel-go/
├── cmd/server/main.go              # точка входа
├── internal/
│   ├── config/                     # YAML-конфигурация, Store
│   ├── models/                     # общие модели данных
│   ├── sshclient/                  # SSH-клиент
│   ├── servercore/                 # IAM-токен, Nova API, Docker, ВМ, пароли, TTL-кэш
│   ├── graylog/                    # Graylog REST API (PROD/TEST)
│   ├── zeebe/                      # Prometheus (SSH-туннель) + Operate API, multi-env
│   ├── msteams/                    # Adaptive Cards в MS Teams
│   ├── vault/                      # HashiCorp Vault (KV v1/v2, эфемерные, users backend, secret refs)
│   ├── aidiag/                     # ИИ-диагностика + детектор проблем
│   ├── monitor/                    # фоновый мониторинг, алерты, инциденты
│   ├── storage/                    # SQLite (аудит, инциденты, история метрик)
│   ├── users/                      # система пользователей с ролями (Vault-backed)
│   ├── sessions/                   # in-memory сессии (cookie-based)
│   ├── secrets/                    # резолвер секретных ссылок из Vault
│   ├── metrics/                    # Prometheus-метрики панели
│   └── web/                        # HTTP-слой, middleware, SSE, auth, html/template
├── static/                         # CSS, JS
├── config.yaml                     # конфигурация
├── Dockerfile                      # multi-stage build
├── .golangci.yml                   # линтер
├── deploy.ps1                      # удалённый SSH-деплой (NSSM)
└── README.md
```

## Возможности

- **Серверы (ServerCore / Nova API)** — список ВМ, метрики CPU/RAM/Disk, IAM-токен (Keystone), TTL-кэш 30с
- **Docker-контейнеры** — `docker ps`, `docker stats`, start/stop/restart, логи (SSH), топология сетей
- **Graylog** — состояние кластера, ноды, streams, поиск логов (PROD/TEST)
- **Zeebe (Camunda 8)** — метрики через Prometheus (SSH-туннель), процессы/инциденты через Operate API, переключатель PROD/TEST
- **MS Teams** — Adaptive Cards, алерты, часовые отчёты
- **Vault** — каталог секретов KV v1/v2, чтение/запись, эфемерные ключи, отслеживание активных ключей
- **AI-диагностика** — автообнаружение проблем, диагноз через ChatGPT/OpenAI или Koda CLI, auto-resolve с подтверждением
- **Управление ВМ** — создание, удаление, start/stop/restart, консоль, пароли (RSA)
- **Фоновый мониторинг** — каждые 5 минут, немедленные алерты с dedup, часовой сводный отчёт, история инцидентов
- **Аудит операций** — SQLite-лог всех действий пользователя (контейнеры, ВМ, Vault, ephemeral, пользователи), полнотекстовый поиск
- **Аутентификация** — полная система пользователей с ролями (superadmin/admin/user), хранение в Vault, смена пароля при первом входе
- **Управление пользователями** — создание/удаление/смена роли/сброс пароля из админки (только superadmin)
- **Редактирование конфигурации** — изменение config.yaml из UI без перезагрузки службы (admin+)
- **Шифрование секретов** — значения `vault:key` в YAML резолвятся из Vault; миграция секретов одной кнопкой
- **Prometheus /metrics** — экспорт метрик панели (uptime, HTTP-запросы, операции, алерты)
- **TLS-аудит** — страница `/tls`: комплексная проверка — версии TLS и cipher suites на **всех** обнаруженных портах (включая порты Docker и слушающие по `ss`/`netstat`), протокол на порту (HTTPS/TLS/HTTP/TCP), анализ **nginx** (`ssl_protocols`, `listen ssl`) и **Docker** (опубликованные порты), детекция слабых cipher suites (RC4/3DES/CBC-SHA1), рекомендации по усилению TLS, **экспорт отчёта в PDF** одной кнопкой (jsPDF + autotable). Проверка **цепочки сертификатов**: Subject/Issuer, SANs, срок действия (NotBefore/NotAfter), серийный номер, алгоритм подписи, соответствие hostname, самоподписанность, автопродление (Let's Encrypt / Vault PKI), флаги истёк/истекает. Поддержка **ALPN и HTTP/2/HTTP/3** (детекция `h2`/`h3` через ALPN и Alt-Svc), **редиректов HTTP→HTTPS** (301/308). Linux — OpenSSL по SSH; Windows/MikroTik — встроенный сканер **прямым соединением, SSH не используется** (ОС определяется по имени образа из Nova)
- **Staging-TLS** — страница `/staging-tls`: проверка готовности PROD к TLS 1.3. PROD-серверы берутся напрямую из списка ServerCore (по имени «prod»), сканируются на TLS/HTTP/nginx/Docker, собираются версии ПО, проводится нагрузочный TLS 1.3 тест (**перцентили p50/p95/p99 + RPS**), отчёт о проблемах (критические / с обходными путями / рекомендации) и вердикт готовности PROD к включению TLS 1.3, экспорт отчёта в PDF; проверка запускается вручную (кнопки Пуск/Стоп), общий таймаут 5 минут, per-server таймаут 90с, SSH-соединение/команды/HTTP-вызовы к Nova — все уважают context cancellation. Учёт архитектуры: всё за NAT + nginx (TLS 1.2/1.3) наружу — внутренние бэкенды и IIS-серверы не помечаются как проблемы. **Сравнение Docker-образов** между PROD-серверами (digest-аудит на рассинхрон версий контейнеров)
- **Staging-клон PROD** — блок на `/staging-tls`: автосоздание изолированного staging-клона из **резервной копии диска** PROD-сервера (Nova `createImage` snapshot → ожидание `active` → ВМ с тем же flavor/сетью; fallback Cinder volume snapshot + block_device_mapping). Копируются nginx-конфиг и docker-compose.yml (best-effort)
- **Управление ВМ** — полноценная форма создания сервера: образы ОС из **Glance API** (с нормализацией имени: «ubuntu-22.04» → «Ubuntu 22.04», Windows Server/ Debian/CentOS/Rocky/Alma), пресеты-тарифы с авто-заполнением ресурсов, **сети (Neutron)**, **security groups (Neutron)**, **SSH-ключи (Nova os-keypairs)**, автогенерация имени `uz-{env}-{app}-{n}`, действия start/restart/stop/delete
- **Конструктор скриптов** — страница `/script-builder`: визуальный конструктор готовых скриптов **Bash / PowerShell / Ansible / Terraform** из модулей (Docker, Nginx, SSL, firewall, node_exporter, fail2ban, systemd, бэкап, Camunda 8, PostgreSQL, IIS, сеть, security group, ВМ из образа и др.) с вложенной формой параметров, копированием и скачиванием файла
- **Статистика серверов** — реальные метрики CPU/RAM/Disk собираются по SSH и кэшируются (60с), а не берутся из metadata Nova (которые часто пустые); CPU-парсер устойчив к разным версиям `top` (поиск поля `idle` по имени, fallback на `/proc/stat`)
- **Health-check** — `/health` с проверкой всех зависимостей
- **Real-time** — SSE `/ws` для пуша сводных метрик, Chart.js графики на дашборде с SQLite-историей
- **Multi-окружение Zeebe** — раздельные URL PROD/TEST, переключатель в UI
- **Graceful shutdown** — таймаут 15с на активные запросы, корректная остановка фоновых горутин

## Endpoints

| Endpoint | Описание |
|----------|----------|
| `/` | Дашборд (графики, серверы, проблемы) |
| `/login` | Вход в систему |
| `/logout` | Выход |
| `/change-password` | Смена пароля |
| `/users` | Управление пользователями (superadmin) |
| `/servercore` | Серверы и ВМ |
| `/containers` | Docker-контейнеры |
| `/containers/networks` | Docker-сети (топология) |
| `/graylog` | Graylog (PROD/TEST) |
| `/camunda` | Zeebe/Camunda (PROD/TEST) |
| `/vault` | Vault секреты |
| `/ephemeral` | Эфемерные ключи |
| `/ai` | AI-диагностика |
| `/vm-manager` | Управление ВМ: создание из Glance-образов, сети, ключи, действия |
| `/script-builder` | Конструктор скриптов (Bash/PowerShell/Ansible/Terraform) |
| `/system` | Система + редактирование config.yaml + миграция секретов |
| `/logs` | Логи панели |
| `/tls` | TLS-аудит серверов (все порты, HTTP, nginx, Docker) |
| `/staging-tls` | Staging-TLS: клон PROD, нагрузочный тест TLS 1.3, отчёт |
| `/health` | Health-check (JSON) |
| `/metrics` | Prometheus metrics |
| `/ws` | SSE real-time stream |
| `/api/*` | REST API для операций, пользователей, конфигурации |

## Быстрый старт

```powershell
cd panel-go
go build -o paylater-mon.exe ./cmd/server
.\paylater-mon.exe -config config.yaml
```

Панель: `http://localhost:9090`

## Деплой

```powershell
cd panel-go
.\deploy.ps1
```

Деплой на `172.31.32.23` по SSH: сборка → ZIP → SCP → stop/delete старой службы → распаковка → создание NSSM-службы (auto-start) → запуск.

Подробности: [panel-go/README.md](panel-go/README.md)

## Лицензия

MIT License

## Автор

Mikhail Gubin, DevOps
