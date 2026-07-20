# План интеграции Codex Device Login

**Статус:** `PAUSED`  
**Дата фиксации:** 2026-07-20  
**Реализация:** не начата

## Цель

Добавить в WhatServ управляемый запуск официального ChatGPT device-code входа для Codex на выбранной удалённой машине.

Пользователь должен иметь возможность выбрать зарегистрированную машину в защищённой панели WhatServ, запросить device code и подтвердить вход с телефона или другого доверенного устройства. Браузер на целевой машине при этом не требуется.

Официальное подтверждение владельцем аккаунта на странице OpenAI, включая возможные SSO/MFA-проверки, остаётся обязательным и не автоматизируется.

## Главное архитектурное решение

Device-code flow должен запускаться локально на той машине, где впоследствии будет работать Codex. Если инициировать его на сервере WhatServ, сессия будет сохранена на сервере, а не на целевой машине.

Поэтому на каждой целевой машине устанавливается отдельный `whatserv-codex-agent`, работающий под тем же пользователем ОС, под которым запускаются Codex CLI или IDE extension.

```text
WhatServ admin
    │  start login(target_id)
    ▼
WhatServ control-plane
    │  outbound agent channel
    ▼
whatserv-codex-agent на целевой машине
    │  stdio JSON-RPC
    ▼
локальный codex app-server
    │
    ├─ account/login/start: chatgptDeviceCode
    ├─ credentials сохраняются локально
    └─ в WhatServ возвращаются только code/URL/status
```

## Официальный Codex flow

Агент запускает локальный `codex app-server`, выполняет обязательный `initialize`, затем отправляет:

```json
{
  "method": "account/login/start",
  "id": 4,
  "params": { "type": "chatgptDeviceCode" }
}
```

Ожидаемый ответ:

```json
{
  "id": 4,
  "result": {
    "type": "chatgptDeviceCode",
    "loginId": "<uuid>",
    "verificationUrl": "https://auth.openai.com/codex/device",
    "userCode": "ABCD-1234"
  }
}
```

После подтверждения агент получает уведомления `account/login/completed` и `account/updated`. WhatServ получает только конечный статус, но не OAuth credentials.

Документация:

- [Codex App Server — Auth endpoints](https://learn.chatgpt.com/docs/app-server#auth-endpoints)
- [Codex Authentication](https://learn.chatgpt.com/docs/auth)
- [Codex CLI commands](https://learn.chatgpt.com/docs/developer-commands#codex-login)

## Компоненты будущей реализации

### 1. WhatServ control-plane

- учёт зарегистрированных целевых машин;
- одноразовое enrollment-подключение агента;
- очередь строго типизированных команд;
- создание, отмена и отслеживание login request;
- защищённая admin-страница device code;
- аудит действий без сохранения кода или токенов;
- отзыв сертификата/доступа агента.

### 2. `whatserv-codex-agent`

- отдельный cross-platform процесс рядом с Codex;
- исходящее соединение к WhatServ, без входящих портов;
- запуск `codex app-server` только через stdio;
- минимальный allowlist JSON-RPC методов авторизации;
- локальное хранение Codex credentials штатными средствами;
- heartbeat, reconnect, timeout, cancel и status reporting;
- отсутствие generic shell/remote-execution возможностей.

### 3. Admin UI

- список зарегистрированных машин;
- online/offline, версия агента и версия Codex;
- локальный auth status без токенов;
- действие **Войти через ChatGPT**;
- имя и fingerprint целевой машины;
- официальный `verificationUrl`, `userCode` и countdown;
- предупреждение о device-code phishing;
- кнопка отмены;
- итог `authenticated`, `failed`, `cancelled` или `expired`.

Device code не должен отображаться на существующей долгоживущей странице `/inbox/{phone}/{token}` или передаваться через WhatsApp. Эти подсистемы остаются разными security domains.

## Предварительный API WhatServ

### Admin API

```http
POST /admin/api/codex/targets
POST /admin/api/codex/targets/{target_id}/revoke
GET  /admin/api/codex/targets

POST /admin/api/codex/login-requests
GET  /admin/api/codex/login-requests/{request_id}
POST /admin/api/codex/login-requests/{request_id}/cancel
```

Создание запроса:

```json
{
  "target_id": "target-uuid"
}
```

Безопасный ответ UI:

```json
{
  "request_id": "request-uuid",
  "target_name": "DEV-PC-12",
  "state": "waiting_for_user",
  "verification_url": "https://auth.openai.com/codex/device",
  "user_code": "ABCD-1234",
  "expires_at": "2026-07-20T15:10:00Z"
}
```

### Target-agent protocol

Разрешённые команды сервера:

- `login.start`;
- `login.cancel`;
- `login.status`;
- `agent.revoke`.

Разрешённые события агента:

- `agent.register`;
- `agent.heartbeat`;
- `command.ack` / `command.nack`;
- `login.status`.

Каждое сообщение должно содержать версию протокола, уникальный `messageId`, `correlationId`, `agentId`, время создания и срок действия. Повторные `messageId` отклоняются.

## Предварительная модель данных

### `codex_targets`

- `id`;
- `display_name`;
- `owner`;
- `enabled`;
- `public_key_fingerprint`;
- `agent_credential_hash` или client certificate identity;
- `agent_version`;
- `codex_version`;
- `last_seen_at`;
- `last_error_code`;
- timestamps.

### `codex_login_requests`

- `id`;
- `target_id`;
- `requested_by`;
- `state`;
- `expires_at`;
- `completed_at`;
- `safe_error_code`;
- timestamps.

`verificationUrl` и `userCode` предпочтительно держать только в памяти/Redis до expiry. Если потребуется переживать рестарт, они шифруются отдельным ключом и удаляются сразу после terminal state.

## Состояния

```text
queued
  → claimed
  → starting
  → waiting_for_user
  → authenticated

Любой активный state
  → failed | cancelled | expired
```

Ограничения:

- только один активный login request на target;
- короткий TTL, окончательное значение берётся из Codex/OpenAI flow;
- start/cancel идемпотентны;
- после завершения code/URL немедленно удаляются;
- reconnect не должен повторно запускать уже подтверждённый flow.

## Неподлежащие нарушению границы безопасности

WhatServ никогда не принимает, не хранит, не логирует и не пересылает:

- пароль ChatGPT;
- MFA/TOTP/passkey/recovery code;
- ChatGPT cookies;
- OAuth access token или refresh token;
- `auth.json`;
- содержимое `CODEX_HOME`;
- произвольные JSON-RPC сообщения или stderr app-server.

Дополнительные требования:

- admin-доступ через HTTPS, VPN/allowlist и в будущем SSO/MFA;
- отдельная идентификация каждого агента, без общего `INTERNAL_API_TOKEN`;
- одноразовый enrollment secret;
- outbound-only соединение агента;
- mTLS и ротация сертификатов в production;
- agent-side allowlist фиксированных команд;
- имя, owner и fingerprint машины рядом с device code;
- предупреждение: вводить только код, запрос которого оператор инициировал лично;
- append-only аудит без device code, URL query и credentials;
- предпочтительное локальное хранение Codex credentials в OS keyring;
- `forced_login_method = "chatgpt"` для управляемых установок;
- при необходимости `forced_chatgpt_workspace_id`.

Автоматизация браузерного входа, ввода MFA или передача `auth.json` между машинами не входят в проект.

## Этапы реализации

### MVP

1. Windows user-mode агент, запускаемый при входе пользователя.
2. Зафиксированная и проверенная версия Codex.
3. Stdio-адаптер `codex app-server`.
4. Одноразовый enrollment и target-scoped bearer over TLS.
5. Один active login request на target.
6. Start, status, cancel и expiry.
7. Admin UI и аудит.
8. Fake app-server и integration tests.
9. Ручной E2E на отдельном тестовом ChatGPT-аккаунте.

### Production

1. mTLS, сертификаты устройств, rotation/revocation.
2. Подписанный Windows installer и обновления.
3. Linux user-mode/headless варианты.
4. RBAC: viewer/operator/approver/device-admin/auditor.
5. Durable command broker и HA.
6. Матрица совместимости Codex app-server schemas.
7. Аномалия login attempts, rate limits и incident workflow.
8. Поддержка enterprise workspace policies.

## Решения, необходимые перед возобновлением

1. Первый target: только Windows user-mode или сразу Windows + Linux.
2. Способ запуска Windows-агента: Startup/Task Scheduler или подписанный installer.
3. MVP transport: HTTPS long-poll или outbound WSS.
4. Где будет доступна admin-панель: VPN, IP allowlist или SSO proxy.
5. Нужен ли двухэтапный approval для входа на чужую/production машину.
6. Минимальная поддерживаемая версия Codex и политика обновления.

## Точка продолжения

При снятии паузы начать с отдельного ADR и protocol schema, затем реализовать fake app-server и state-machine агента. Только после контрактных тестов добавлять таблицы, API и admin UI в основной WhatServ.
