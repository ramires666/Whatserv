"""FastAPI control plane and protected web interface for WhatServ."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import logging
import re
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, AsyncIterator

import qrcode
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import Settings, get_settings
from .database import Base, create_engine, session_factory
from .models import Account, AuditEvent, Message
from .schemas import (
    IncomingMessage,
    PublicMessage,
    PublicSnapshot,
    PublicTotp,
    WorkerAccount,
    WorkerAccountList,
    WorkerStateUpdate,
)
from .security import (
    PhoneNormalizationError,
    TotpSeedCipher,
    generate_capability_token,
    hash_capability_token,
    mask_phone,
    normalize_phone,
    verify_capability_token,
)
from .totp import DEFAULT_INTERVAL, totp_code, totp_seconds_remaining


logger = logging.getLogger("whatserv")
WEB_DIR = Path(__file__).parent / "web"
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
basic_scheme = HTTPBasic(auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)
PHONE_PATH_RE = re.compile(r"^[1-9]\d{7,14}$")
ALLOWED_WA_STATES = {
    "new",
    "pending_qr",
    "connecting",
    "online",
    "degraded",
    "logged_out",
    "disabled",
    "stopped",
}


class SlidingWindowLimiter:
    """Small single-process guard; production proxy limits remain authoritative."""

    def __init__(self, *, max_buckets: int = 4096) -> None:
        self.max_buckets = max_buckets
        self.hits: dict[str, deque[float]] = {}
        self.lock = asyncio.Lock()

    async def enforce(self, key: str, *, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        cutoff = now - window_seconds
        async with self.lock:
            bucket = self.hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests",
                    headers={"Retry-After": str(window_seconds)},
                )
            bucket.append(now)
            if len(self.hits) > self.max_buckets:
                stale = [name for name, values in self.hits.items() if not values or values[-1] <= cutoff]
                for name in stale:
                    self.hits.pop(name, None)
                while len(self.hits) > self.max_buckets:
                    self.hits.pop(next(iter(self.hits)))


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _secret(settings: Settings, name: str) -> str:
    return getattr(settings, name).get_secret_value()


def _csrf_token(settings: Settings) -> str:
    issued_at = str(int(time.time()))
    payload = f"admin-csrf:{settings.admin_username}:{issued_at}".encode()
    signature = hmac.new(
        _secret(settings, "access_token_pepper").encode(), payload, hashlib.sha256
    ).hexdigest()
    return f"{issued_at}.{signature}"


def _verify_csrf(settings: Settings, token: str, *, max_age: int = 3600) -> bool:
    try:
        issued_at_raw, supplied = token.split(".", 1)
        issued_at = int(issued_at_raw)
    except (AttributeError, TypeError, ValueError):
        return False
    now = int(time.time())
    if issued_at > now + 30 or now - issued_at > max_age:
        return False
    payload = f"admin-csrf:{settings.admin_username}:{issued_at_raw}".encode()
    expected = hmac.new(
        _secret(settings, "access_token_pepper").encode(), payload, hashlib.sha256
    ).hexdigest()
    return secrets.compare_digest(expected, supplied)


def _phone_from_path(phone_digits: str) -> str:
    if not PHONE_PATH_RE.fullmatch(phone_digits):
        raise HTTPException(status_code=404, detail="Not found")
    try:
        return normalize_phone(f"+{phone_digits}")
    except PhoneNormalizationError as exc:
        raise HTTPException(status_code=404, detail="Not found") from exc


def _capability_url(settings: Settings, phone_e164: str, token: str) -> str:
    return f"{settings.public_base_url}/inbox/{phone_e164.removeprefix('+')}/{token}"


def _active_until(value: datetime | None) -> bool:
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value > datetime.now(UTC)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with factory() as session:
        yield session


async def require_admin(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials | None, Depends(basic_scheme)],
) -> str:
    settings: Settings = request.app.state.settings
    await request.app.state.rate_limiter.enforce(
        f"admin:{_client_key(request)}", limit=300, window_seconds=300
    )
    username_ok = credentials is not None and secrets.compare_digest(
        credentials.username.encode(), settings.admin_username.encode()
    )
    password_ok = credentials is not None and secrets.compare_digest(
        credentials.password.encode(), _secret(settings, "admin_password").encode()
    )
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator authentication required",
            headers={"WWW-Authenticate": 'Basic realm="WhatServ admin", charset="UTF-8"'},
        )
    return settings.admin_username


async def require_internal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> None:
    settings: Settings = request.app.state.settings
    valid = (
        credentials is not None
        and credentials.scheme.lower() == "bearer"
        and secrets.compare_digest(
            credentials.credentials.encode(),
            _secret(settings, "internal_api_token").encode(),
        )
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid internal credentials")


async def _authorized_account(
    session: AsyncSession, settings: Settings, phone_digits: str, token: str
) -> Account:
    phone = _phone_from_path(phone_digits)
    account = await session.scalar(select(Account).where(Account.phone_e164 == phone))
    pepper = _secret(settings, "access_token_pepper")
    if (
        account is None
        or not account.enabled
        or not _active_until(account.capability_expires_at)
        or not verify_capability_token(token, account.access_token_hash, pepper)
    ):
        raise HTTPException(status_code=404, detail="Not found")
    return account


def _sanitize_metadata(raw: dict | None) -> dict | None:
    if not raw:
        return None
    result: dict[str, str | int | float | bool | None] = {}
    for key in ("remote_jid", "participant", "push_name"):
        value = raw.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value[:512] if isinstance(value, str) else value
    return result or None


def _sender_phone(raw: str | None) -> str | None:
    digits = "".join(character for character in (raw or "") if character.isdigit())
    if not (8 <= len(digits) <= 15):
        return None
    try:
        return normalize_phone(f"+{digits}")
    except PhoneNormalizationError:
        return None


def create_app(*, settings_override: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings = settings_override or get_settings()
        engine = create_engine(settings.database_url)
        app.state.settings = settings
        app.state.engine = engine
        app.state.session_factory = session_factory(engine)
        app.state.rate_limiter = SlidingWindowLimiter()
        if settings.auto_create_schema:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        yield
        await engine.dispose()

    app = FastAPI(
        title="WhatServ",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        if request.url.path.startswith(("/admin", "/inbox", "/api/public")):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/healthz")
    async def healthz(session: Annotated[AsyncSession, Depends(get_session)]):
        try:
            await session.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unhealthy"}, status_code=503)
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse("/admin", status_code=307)

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        account_rows = list(
            await session.scalars(select(Account).order_by(Account.created_at.desc()))
        )
        cipher = TotpSeedCipher(_secret(request.app.state.settings, "qr_fernet_key"))
        accounts = []
        for account in account_rows:
            has_qr = bool(account.encrypted_qr_data and _active_until(account.qr_expires_at))
            pairing_code = None
            if account.encrypted_pairing_code and _active_until(account.qr_expires_at):
                try:
                    pairing_code = cipher.decrypt(account.encrypted_pairing_code)
                except Exception:
                    logger.warning("pairing_code_decryption_failed", extra={"account_id": account.id})
            accounts.append({"account": account, "has_qr": has_qr, "pairing_code": pairing_code})
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={
                "accounts": accounts,
                "csrf_token": _csrf_token(request.app.state.settings),
                "notice": request.query_params.get("notice"),
            },
        )

    @app.post("/admin/accounts", response_class=HTMLResponse)
    async def create_account(
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        label: Annotated[str, Form(min_length=1, max_length=120)],
        phone: Annotated[str, Form(min_length=8, max_length=40)],
        csrf_token: Annotated[str, Form()],
        totp_secret: Annotated[str, Form(max_length=256)] = "",
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        try:
            phone_e164 = normalize_phone(phone)
        except PhoneNormalizationError as exc:
            raise HTTPException(status_code=422, detail="Use a valid international number starting with +") from exc

        encrypted_seed = None
        normalized_seed = "".join(totp_secret.split()).upper()
        if normalized_seed:
            try:
                # Validate the Base32 seed before encrypting and persisting it.
                totp_code(normalized_seed, for_time=0)
            except Exception as exc:
                raise HTTPException(status_code=422, detail="Invalid TOTP Base32 secret") from exc
            encrypted_seed = TotpSeedCipher(_secret(settings, "fernet_key")).encrypt(
                normalized_seed
            )

        token = generate_capability_token()
        expires_at = datetime.now(UTC) + timedelta(hours=settings.capability_ttl_hours)
        account = Account(
            phone_e164=phone_e164,
            label=label.strip(),
            enabled=True,
            access_token_hash=hash_capability_token(
                token, _secret(settings, "access_token_pepper")
            ),
            capability_expires_at=expires_at,
            encrypted_totp_secret=encrypted_seed,
            wa_state="new",
        )
        session.add(account)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="This phone is already registered") from exc
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="account.created",
                actor=settings.admin_username,
            )
        )
        await session.commit()
        return templates.TemplateResponse(
            request=request,
            name="capability.html",
            context={
                "label": account.label,
                "capability_url": _capability_url(settings, account.phone_e164, token),
                "expires_at": expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            },
        )

    @app.post("/admin/accounts/{account_id}/rotate-link", response_class=HTMLResponse)
    async def rotate_link(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        token = generate_capability_token()
        account.access_token_hash = hash_capability_token(
            token, _secret(settings, "access_token_pepper")
        )
        expires_at = datetime.now(UTC) + timedelta(hours=settings.capability_ttl_hours)
        account.capability_expires_at = expires_at
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="capability.rotated",
                actor=settings.admin_username,
            )
        )
        await session.commit()
        return templates.TemplateResponse(
            request=request,
            name="capability.html",
            context={
                "label": account.label or account.phone_e164,
                "capability_url": _capability_url(settings, account.phone_e164, token),
                "expires_at": expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            },
        )

    @app.post("/admin/accounts/{account_id}/toggle")
    async def toggle_account(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        account.enabled = not account.enabled
        account.wa_state = "new" if account.enabled else "disabled"
        if not account.enabled:
            account.encrypted_qr_data = None
            account.encrypted_pairing_code = None
            account.qr_expires_at = None
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="account.enabled" if account.enabled else "account.disabled",
                actor=settings.admin_username,
            )
        )
        await session.commit()
        return RedirectResponse("/admin?notice=Account+updated", status_code=303)

    @app.get("/admin/accounts/{account_id}/qr.png")
    async def account_qr(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        account = await session.get(Account, account_id)
        if (
            account is None
            or not account.encrypted_qr_data
            or not _active_until(account.qr_expires_at)
        ):
            raise HTTPException(status_code=404, detail="QR code is not available")
        try:
            qr_payload = TotpSeedCipher(
                _secret(request.app.state.settings, "qr_fernet_key")
            ).decrypt(account.encrypted_qr_data)
        except Exception as exc:
            raise HTTPException(status_code=404, detail="QR code is not available") from exc
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=7,
            border=3,
        )
        qr.add_data(qr_payload)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return Response(
            buffer.getvalue(),
            media_type="image/png",
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    @app.get("/inbox/{phone_digits}/{token}", response_class=HTMLResponse)
    async def inbox_page(
        phone_digits: str,
        token: str,
        request: Request,
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        settings: Settings = request.app.state.settings
        await request.app.state.rate_limiter.enforce(
            f"public:{phone_digits}:{_client_key(request)}", limit=180, window_seconds=60
        )
        account = await _authorized_account(session, settings, phone_digits, token)
        account.capability_last_used_at = datetime.now(UTC)
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="inbox.opened",
                actor="capability",
            )
        )
        await session.commit()
        return templates.TemplateResponse(
            request=request,
            name="inbox.html",
            context={
                "label": account.label or "WhatsApp",
                "masked_phone": mask_phone(account.phone_e164),
                "snapshot_url": f"/api/public/{phone_digits}/{token}/snapshot",
            },
        )

    @app.get("/api/public/{phone_digits}/{token}/snapshot", response_model=PublicSnapshot)
    async def public_snapshot(
        phone_digits: str,
        token: str,
        request: Request,
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        settings: Settings = request.app.state.settings
        await request.app.state.rate_limiter.enforce(
            f"public:{phone_digits}:{_client_key(request)}", limit=180, window_seconds=60
        )
        account = await _authorized_account(session, settings, phone_digits, token)
        rows = list(
            await session.scalars(
                select(Message)
                .where(Message.account_id == account.id)
                .order_by(Message.received_at.desc())
                .limit(settings.message_page_size)
            )
        )
        messages = [
            PublicMessage(
                id=item.id,
                sender_phone=item.sender_e164,
                body=item.text,
                received_at=item.received_at,
                message_type=item.message_type,
            )
            for item in rows
        ]
        public_totp = None
        if account.encrypted_totp_secret:
            try:
                seed = TotpSeedCipher(_secret(settings, "fernet_key")).decrypt(
                    account.encrypted_totp_secret
                )
                public_totp = PublicTotp(
                    code=totp_code(seed),
                    valid_for=totp_seconds_remaining(),
                    period=DEFAULT_INTERVAL,
                )
            except Exception:
                logger.exception("totp_generation_failed", extra={"account_id": account.id})
        return PublicSnapshot(
            whatsapp_state=account.wa_state,
            messages=messages,
            totp=public_totp,
        )

    @app.get(
        "/api/internal/accounts",
        response_model=WorkerAccountList,
        dependencies=[Depends(require_internal)],
    )
    async def worker_accounts(session: Annotated[AsyncSession, Depends(get_session)]):
        accounts = list(await session.scalars(select(Account).order_by(Account.id)))
        return WorkerAccountList(items=[WorkerAccount.model_validate(item) for item in accounts])

    @app.post(
        "/api/internal/accounts/{account_id}/state",
        dependencies=[Depends(require_internal)],
    )
    async def update_worker_state(
        account_id: str,
        request: Request,
        payload: WorkerStateUpdate,
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        if payload.state not in ALLOWED_WA_STATES:
            raise HTTPException(status_code=422, detail="Unknown WhatsApp state")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        if not account.enabled:
            account.wa_state = "disabled"
            account.encrypted_qr_data = None
            account.encrypted_pairing_code = None
            account.qr_expires_at = None
            await session.commit()
            return {"ok": True, "ignored": True}
        old_state = account.wa_state
        account.wa_state = payload.state
        if payload.qr_code is not None:
            account.encrypted_qr_data = TotpSeedCipher(
                _secret(request.app.state.settings, "qr_fernet_key")
            ).encrypt(payload.qr_code)
            account.qr_expires_at = datetime.now(UTC) + timedelta(
                seconds=request.app.state.settings.qr_ttl_seconds
            )
        else:
            account.encrypted_qr_data = None
            account.qr_expires_at = None
        if payload.pairing_code is not None:
            account.encrypted_pairing_code = TotpSeedCipher(
                _secret(request.app.state.settings, "qr_fernet_key")
            ).encrypt(payload.pairing_code)
        else:
            account.encrypted_pairing_code = None
        if payload.last_error is not None:
            account.last_error = payload.last_error[:1000]
        if payload.state in {"online", "disabled", "logged_out", "stopped"}:
            account.encrypted_qr_data = None
            account.encrypted_pairing_code = None
            account.qr_expires_at = None
        if payload.state == "online":
            account.last_error = None
        if old_state != payload.state:
            session.add(
                AuditEvent(
                    account_id=account.id,
                    event_type="whatsapp.state_changed",
                    actor="whatsapp-worker",
                    details={"from": old_state, "to": payload.state},
                )
            )
        await session.commit()
        return {"ok": True}

    @app.post(
        "/api/internal/messages",
        dependencies=[Depends(require_internal)],
    )
    async def receive_message(
        payload: IncomingMessage,
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        account = await session.get(Account, payload.account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        existing = await session.scalar(
            select(Message.id).where(
                Message.account_id == payload.account_id,
                Message.external_id == payload.external_id,
            )
        )
        if existing:
            return {"accepted": False, "duplicate": True}
        received_at = payload.received_at
        if received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=UTC)
        message = Message(
            account_id=payload.account_id,
            external_id=payload.external_id,
            sender_e164=_sender_phone(payload.sender_phone),
            text=payload.body,
            message_type=payload.message_type,
            received_at=received_at,
            raw_metadata=_sanitize_metadata(payload.raw_metadata),
        )
        session.add(message)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return {"accepted": False, "duplicate": True}
        return {"accepted": True, "duplicate": False}

    return app


app = create_app()
