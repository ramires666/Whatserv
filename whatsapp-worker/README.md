# WhatsApp worker

Private Node 22 gateway for ordinary WhatsApp accounts. It is deliberately not exposed to the Internet: FastAPI owns the public API and UI.

## Required configuration

`BACKEND_INTERNAL_URL` is the private backend URL and `INTERNAL_API_TOKEN` is its bearer token. Optional values: `WA_SESSION_DIR` (default `./auth`), `WA_HEALTH_PORT` (default `3000`), `WA_RECONCILE_INTERVAL_MS` (default `15000`), `LOG_LEVEL` (`debug|info|warn|error`, default `info`).

Authentication is persisted in one directory per account under `WA_SESSION_DIR`. This is an MVP mechanism only: those files are long-lived WhatsApp credentials, must be on an encrypted persistent volume, access-restricted, backed up securely, and never committed, copied into images, or logged. Replace this with encrypted database/KMS-backed auth state before a multi-host deployment.

Incoming messages are written atomically to a local durable outbox before delivery to FastAPI. A backend outage therefore delays display instead of silently dropping messages. Outbox files contain message data until acknowledged and require the same encrypted-volume and access controls as session files.

The backend endpoints are called with the configured bearer token. Account state and QR values are only posted to that backend; the worker never serves QR codes. `/healthz` deliberately contains no account data.
