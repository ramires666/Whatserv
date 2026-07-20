# WhatServ

WhatServ — сервер для одновременного подключения нескольких обычных WhatsApp-аккаунтов, приёма входящих сообщений и выдачи сообщений вместе с текущим Google Authenticator/TOTP-кодом по защищённой индивидуальной ссылке.

В URL присутствует номер аккаунта, как требует текущий сценарий, но номер не является защитой. Ссылка также содержит случайный 256-битный capability-токен, действует ограниченное время и может быть отозвана выпуском новой ссылки.

> [!WARNING]
> Подключение обычных аккаунтов построено на неофициальном WhatsApp Web-клиенте [Baileys](https://github.com/WhiskeySockets/Baileys). Оно не поддерживается WhatsApp и может перестать работать после изменения протокола или привести к ограничению аккаунта. Проект принимает только входящие сообщения: рассылки и автоответы намеренно не реализованы. Для официально поддерживаемой интеграции используйте WhatsApp Business Platform.

## Что уже реализовано

- FastAPI-веб-интерфейс и PostgreSQL для аккаунтов, входящих сообщений и аудита;
- отдельный лёгкий Node.js/Baileys-шлюз: один Multi-Device socket на аккаунт, без Chromium;
- удобная QR-привязка аккаунта в защищённой admin-панели;
- состояния `new`, `pending_qr`, `connecting`, `online`, `degraded`, `logged_out`;
- автоматическая перепривязка с новым QR после logout;
- durable outbox: сообщения переживают временную недоступность FastAPI;
- дедупликация сообщений по WhatsApp ID;
- TOTP по RFC 6238, обратный отсчёт до смены кода;
- шифрование TOTP-секретов и короткоживущих QR-данных разными Fernet-ключами;
- ограниченные по времени, отзываемые публичные ссылки; в БД хранится только HMAC-отпечаток токена;
- `no-store`, CSP, `no-referrer`, CSRF-защита admin-форм и отдельный internal bearer token;
- Alembic-миграции, Docker Compose и автоматические тесты.

## Архитектура

```mermaid
flowchart LR
    browser["Браузер"]
    proxy["Reverse proxy"]
    api["FastAPI"]
    database[("PostgreSQL")]
    gateway["Node.js / Baileys<br/>1 socket и auth state на аккаунт"]

    browser -->|"HTTPS"| proxy
    proxy --> api
    api --> database
    gateway -->|"Private HTTP + bearer"| api
```

FastAPI — единственный публичный слой. Baileys-шлюз не публикует API наружу и только получает список включённых аккаунтов, отправляет состояния/QR и доставляет входящие сообщения.

## Быстрый запуск

Требования: Docker Engine с Compose v2+, домен и HTTPS reverse proxy для production.

1. Создайте конфигурацию:

   ```powershell
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

2. В `.env` замените все `CHANGE_ME` значения. Для `FERNET_KEY` и `QR_FERNET_KEY` сгенерируйте два разных Fernet-ключа. Для `ADMIN_PASSWORD`, `INTERNAL_API_TOKEN` и `ACCESS_TOKEN_PEPPER` используйте разные длинные случайные значения. Пароль PostgreSQL должен совпадать в `POSTGRES_PASSWORD` и `DATABASE_URL`.

3. Укажите внешний адрес в `PUBLIC_BASE_URL`. В production принимается только `https://`. Для локальной проверки можно явно поставить:

   ```dotenv
   PUBLIC_BASE_URL=http://127.0.0.1:8000
   ALLOW_INSECURE_HTTP=true
   ```

4. Запустите сервисы:

   ```powershell
   docker compose up --build -d
   docker compose ps
   ```

5. Откройте `http://127.0.0.1:8000/admin` и войдите с `ADMIN_USERNAME` / `ADMIN_PASSWORD`.

## Привязка WhatsApp через QR

1. Добавьте название, телефон в международном формате (`+770...`) и при необходимости Base32-секрет TOTP.
2. Сохраните показанную индивидуальную ссылку — полностью она показывается только один раз.
3. Подождите до 15 секунд и обновите admin-страницу. На карточке появится QR.
4. На телефоне откройте WhatsApp → **Связанные устройства** → **Привязка устройства** и отсканируйте QR.
5. Статус изменится на `online`, QR автоматически исчезнет. При истечении QR шлюз выдаст свежий; после выхода связанного устройства будет запрошена новая привязка.

QR доступен только admin-пользователю, хранится в БД зашифрованным и имеет короткий TTL (`QR_TTL_SECONDS`, по умолчанию 120 секунд).

## Индивидуальная страница

Созданная ссылка имеет вид:

```text
https://example.com/inbox/77001234567/<случайный-секрет>
```

Страница показывает состояние WhatsApp, последние входящие сообщения и текущий TOTP-код. Она обновляется каждые три секунды. По умолчанию ссылка действует 720 часов; срок задаётся `CAPABILITY_TTL_HOURS`. Кнопка **Новая ссылка** немедленно отзывает старую.

## Проверки разработчика

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Push-Location backend
..\.venv\Scripts\python.exe -m pytest -q
Pop-Location

Push-Location whatsapp-worker
npm.cmd ci
npm.cmd test
Pop-Location

$env:WHATSERV_ENV_FILE='.env.example'
docker compose --env-file .env.example config --quiet
```

Python-тесты используют SQLite только как изолированную тестовую БД. Production-контейнер перед стартом выполняет `alembic upgrade head` для PostgreSQL.

## Production checklist

- Завершайте TLS на reverse proxy, включите HSTS и rate limits для `/admin`, `/inbox` и `/api/public`.
- Не публикуйте порт 8000 напрямую: Compose привязывает его только к `127.0.0.1`.
- Ограничьте `/admin` VPN/IP allowlist и используйте уникальный длинный пароль.
- Храните `.env` в secret manager, не в Git. Не меняйте Fernet-ключи без процедуры re-encryption.
- Разместите `postgres-data` и `whatsapp-sessions` на шифрованном диске; файлы Baileys являются полноценными credentials связанного устройства.
- Настройте резервные копии PostgreSQL и сессионного volume, доступ к ним — по принципу минимальных привилегий.
- Обеспечьте синхронизацию времени хоста (NTP), иначе TOTP будет неверным.
- Настройте срок хранения сообщений согласно требованиям к персональным данным.
- Следите за обновлениями и security advisories [Baileys](https://github.com/WhiskeySockets/Baileys/security).

Один worker рассчитан на десятки аккаунтов, но запускать две его реплики на одном наборе аккаунтов нельзя: обе откроют одинаковые linked-device сессии. Для multi-host/HA следующая ступень — распределённая аренда аккаунтов (leases) и зашифрованное SQL/KMS-хранилище Signal keys вместо `useMultiFileAuthState`.

## Подготовка первого push

Репозиторий уже содержит `.gitignore`, `.gitattributes`, EditorConfig и CI. После назначения remote:

```powershell
git remote add origin <URL-репозитория>
git push -u origin main
```

## Правовые ограничения

Используйте только аккаунты, владельцы которых явно разрешили подключение. Не используйте проект для спама, массовых сообщений, обхода ограничений или несанкционированного доступа. Ознакомьтесь с [WhatsApp Terms of Service](https://www.whatsapp.com/legal/terms-of-service) и предупреждениями проекта Baileys.
