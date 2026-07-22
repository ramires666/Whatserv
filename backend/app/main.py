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
from uuid import uuid4

import qrcode
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import Settings, get_settings
from .database import Base, create_engine, session_factory
from .models import Account, AuditEvent, Message
from .schemas import (
    IncomingMessage,
    PublicCredentials,
    PublicMessage,
    PublicSnapshot,
    PublicTotp,
    WorkerAccount,
    WorkerAccountList,
    WorkerStateUpdate,
)
from .security import (
    CredentialCipher,
    PhoneNormalizationError,
    TotpSeedCipher,
    generate_capability_token,
    hash_capability_token,
    normalize_phone,
    verify_capability_token,
)
from .totp import (
    DEFAULT_INTERVAL,
    TotpInputError,
    normalize_totp_input,
    totp_code,
    totp_seconds_remaining,
    totp_valid_until,
)


logger = logging.getLogger("whatserv")
WEB_DIR = Path(__file__).parent / "web"
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
STATIC_VERSION = hashlib.sha256(
    b"".join(
        path.read_bytes()
        for path in sorted((WEB_DIR / "static").iterdir())
        if path.is_file()
    )
).hexdigest()[:12]
templates.env.globals["static_version"] = STATIC_VERSION
basic_scheme = HTTPBasic(auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)
PHONE_PATH_RE = re.compile(r"^[1-9]\d{7,14}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}$")
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


def _encrypt_totp_input(settings: Settings, value: str) -> str | None:
    if len(value) > 2048:
        raise TotpInputError("TOTP input is too long")
    normalized = normalize_totp_input(value)
    if normalized is None:
        return None
    return TotpSeedCipher(_secret(settings, "fernet_key")).encrypt(normalized)


def _normalize_login_email(value: str) -> str:
    if not isinstance(value, str) or len(value) > 254:
        raise ValueError("invalid email")
    normalized = value.strip().casefold()
    if not EMAIL_RE.fullmatch(normalized):
        raise ValueError("invalid email")
    return normalized


def _encrypt_login_password(settings: Settings, value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("invalid password")
    return CredentialCipher(_secret(settings, "credential_fernet_key")).encrypt(value)


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


def _metadata_text(raw: dict | None, key: str) -> str | None:
    value = (raw or {}).get(key)
    return value if isinstance(value, str) and value else None


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

    async def render_admin(
        request: Request,
        session: AsyncSession,
        *,
        notice: str | None = None,
        error: str | None = None,
        form_values: dict[str, str] | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        account_rows = list(
            await session.scalars(select(Account).order_by(Account.created_at.desc()))
        )
        cipher = TotpSeedCipher(_secret(request.app.state.settings, "qr_fernet_key"))
        credential_cipher = CredentialCipher(
            _secret(request.app.state.settings, "credential_fernet_key")
        )
        token_pepper = _secret(request.app.state.settings, "access_token_pepper")
        accounts = []
        auto_refresh = False
        for account in account_rows:
            has_qr = bool(account.encrypted_qr_data and _active_until(account.qr_expires_at))
            pairing_code = None
            if account.encrypted_pairing_code and _active_until(account.qr_expires_at):
                try:
                    pairing_code = cipher.decrypt(account.encrypted_pairing_code)
                except Exception:
                    logger.warning(
                        "pairing_code_decryption_failed", extra={"account_id": account.id}
                    )
            capability_url = None
            if account.encrypted_access_token and _active_until(account.capability_expires_at):
                try:
                    token = credential_cipher.decrypt(account.encrypted_access_token)
                    if verify_capability_token(token, account.access_token_hash, token_pepper):
                        capability_url = _capability_url(
                            request.app.state.settings, account.phone_e164, token
                        )
                except Exception:
                    logger.warning(
                        "admin_capability_decryption_failed",
                        extra={"account_id": account.id},
                    )
            accounts.append(
                {
                    "account": account,
                    "has_qr": has_qr,
                    "pairing_code": pairing_code,
                    "has_totp": bool(account.encrypted_totp_secret),
                    "has_credentials": bool(
                        account.login_email and account.encrypted_login_password
                    ),
                    "capability_url": capability_url,
                    "has_recoverable_link": capability_url is not None,
                }
            )
            if account.wa_state in {
                "new",
                "logout_requested",
                "logged_out",
                "pending_qr",
                "connecting",
            }:
                auto_refresh = True
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={
                "accounts": accounts,
                "csrf_token": _csrf_token(request.app.state.settings),
                "notice": notice,
                "error": error,
                "form_values": form_values or {},
                "open_create_form": bool(form_values),
                "auto_refresh": auto_refresh,
            },
            status_code=status_code,
        )

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        return await render_admin(
            request,
            session,
            notice=request.query_params.get("notice"),
        )

    @app.get("/admin/account-summaries")
    async def admin_account_summaries(
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        settings: Settings = request.app.state.settings
        now = datetime.now(UTC)
        accounts = list(
            await session.scalars(select(Account).order_by(Account.created_at.desc()))
        )
        ranked_messages = (
            select(
                Message.account_id,
                Message.text,
                Message.sender_e164,
                Message.raw_metadata,
                Message.received_at,
                Message.message_type,
                func.row_number()
                .over(
                    partition_by=Message.account_id,
                    order_by=(Message.received_at.desc(), Message.id.desc()),
                )
                .label("message_rank"),
            )
            .subquery()
        )
        latest_rows = await session.execute(
            select(ranked_messages).where(ranked_messages.c.message_rank == 1)
        )
        latest_by_account = {row.account_id: row for row in latest_rows}
        items = []
        for account in accounts:
            latest = latest_by_account.get(account.id)
            current_totp = None
            if account.encrypted_totp_secret:
                try:
                    seed = TotpSeedCipher(_secret(settings, "fernet_key")).decrypt(
                        account.encrypted_totp_secret
                    )
                    current_totp = totp_code(seed, for_time=now)
                except Exception:
                    logger.exception(
                        "admin_totp_generation_failed", extra={"account_id": account.id}
                    )
            latest_message = None
            if latest is not None:
                latest_message = {
                    "body": latest.text,
                    "sender_name": _metadata_text(latest.raw_metadata, "push_name"),
                    "sender_phone": latest.sender_e164,
                    "sender_jid": _metadata_text(latest.raw_metadata, "remote_jid"),
                    "received_at": latest.received_at,
                    "message_type": latest.message_type,
                }
            items.append(
                {
                    "account_id": account.id,
                    "totp": current_totp,
                    "latest_message": latest_message,
                }
            )
        return {"items": items, "server_time": now}

    @app.post("/admin/accounts", response_class=HTMLResponse)
    async def create_account(
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        phone: Annotated[str, Form(min_length=8, max_length=40)],
        csrf_token: Annotated[str, Form()],
        login_email: Annotated[str, Form()] = "",
        login_password: Annotated[str, Form()] = "",
        owner_name: Annotated[str, Form()] = "",
        comment: Annotated[str, Form()] = "",
        label: Annotated[str, Form(max_length=120)] = "",
        totp_secret: Annotated[str, Form()] = "",
        without_totp: Annotated[bool, Form()] = False,
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        if len(owner_name) > 120 or len(comment) > 2000:
            return await render_admin(
                request,
                session,
                error="Поле «У кого» или комментарий слишком длинные.",
                form_values={
                    "login_email": login_email,
                    "phone": phone,
                    "label": label,
                    "owner_name": owner_name,
                    "comment": comment[:2000],
                },
                status_code=422,
            )
        try:
            normalized_email = _normalize_login_email(login_email)
            encrypted_password = _encrypt_login_password(settings, login_password)
        except ValueError:
            return await render_admin(
                request,
                session,
                error="Введите корректный email и непустой пароль.",
                form_values={"login_email": login_email, "phone": phone},
                status_code=422,
            )
        try:
            phone_e164 = normalize_phone(phone)
        except PhoneNormalizationError as exc:
            return await render_admin(
                request,
                session,
                error="Введите телефон в международном формате, начиная с +.",
                form_values={"login_email": normalized_email, "phone": phone},
                status_code=422,
            )

        if without_totp and totp_secret.strip():
            return await render_admin(
                request,
                session,
                error="Либо укажите TOTP, либо отметьте аккаунт без TOTP.",
                form_values={"login_email": normalized_email, "phone": phone},
                status_code=422,
            )
        if not without_totp and not totp_secret.strip():
            return await render_admin(
                request,
                session,
                error="TOTP нужен по умолчанию. Для исключения отметьте «Аккаунт без TOTP».",
                form_values={"login_email": normalized_email, "phone": phone},
                status_code=422,
            )
        try:
            encrypted_seed = (
                None
                if without_totp
                else _encrypt_totp_input(settings, totp_secret)
            )
        except TotpInputError:
            return await render_admin(
                request,
                session,
                error="TOTP не сохранён. Проверьте Base32-секрет или ссылку otpauth://totp.",
                form_values={"login_email": normalized_email, "phone": phone},
                status_code=422,
            )

        token = generate_capability_token()
        expires_at = datetime.now(UTC) + timedelta(hours=settings.capability_ttl_hours)
        account = Account(
            phone_e164=phone_e164,
            label=(label.strip() or normalized_email)[:120],
            owner_name=owner_name.strip() or None,
            comment=comment.strip() or None,
            login_email=normalized_email,
            encrypted_login_password=encrypted_password,
            enabled=True,
            access_token_hash=hash_capability_token(
                token, _secret(settings, "access_token_pepper")
            ),
            encrypted_access_token=CredentialCipher(
                _secret(settings, "credential_fernet_key")
            ).encrypt(token),
            capability_expires_at=expires_at,
            encrypted_totp_secret=encrypted_seed,
            wa_state="new",
        )
        session.add(account)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            return await render_admin(
                request,
                session,
                error="Этот телефон или email уже зарегистрирован.",
                form_values={"login_email": normalized_email, "phone": phone},
                status_code=409,
            )
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

    @app.post("/admin/accounts/{account_id}/metadata")
    async def update_account_metadata(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
        phone: Annotated[str | None, Form(max_length=40)] = None,
        label: Annotated[str | None, Form(max_length=120)] = None,
        owner_name: Annotated[str, Form()] = "",
        comment: Annotated[str, Form()] = "",
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        if len(owner_name) > 120 or len(comment) > 2000:
            return await render_admin(
                request,
                session,
                error="Данные аккаунта не изменены: превышена допустимая длина.",
                status_code=422,
            )
        try:
            phone_e164 = account.phone_e164 if phone is None else normalize_phone(phone)
        except PhoneNormalizationError:
            return await render_admin(
                request,
                session,
                error="Данные аккаунта не изменены: проверьте телефон в международном формате.",
                status_code=422,
            )
        previous_phone = account.phone_e164
        account.phone_e164 = phone_e164
        if label is not None:
            account.label = label.strip() or None
        account.owner_name = owner_name.strip() or None
        account.comment = comment.strip() or None
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="account.details.updated",
                actor=settings.admin_username,
                details={"phone_changed": previous_phone != phone_e164},
            )
        )
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return await render_admin(
                request,
                session,
                error="Данные аккаунта не изменены: этот телефон уже зарегистрирован.",
                status_code=409,
            )
        return RedirectResponse("/admin?notice=Account+details+updated", status_code=303)

    @app.post("/admin/accounts/{account_id}/credentials")
    async def update_credentials(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
        login_email: Annotated[str, Form()] = "",
        login_password: Annotated[str, Form()] = "",
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        try:
            normalized_email = _normalize_login_email(login_email)
            encrypted_password = (
                _encrypt_login_password(settings, login_password)
                if login_password
                else account.encrypted_login_password
            )
            if encrypted_password is None:
                raise ValueError("password is required")
        except ValueError:
            return await render_admin(
                request,
                session,
                error="Логин не изменён: проверьте email и пароль.",
                status_code=422,
            )
        account.login_email = normalized_email
        account.encrypted_login_password = encrypted_password
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="account.credentials.updated",
                actor=settings.admin_username,
            )
        )
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return await render_admin(
                request,
                session,
                error="Этот email уже привязан к другому аккаунту.",
                status_code=409,
            )
        return RedirectResponse("/admin?notice=Credentials+updated", status_code=303)

    @app.get("/admin/accounts/{account_id}/credentials")
    async def reveal_admin_credentials(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        if not account.login_email or not account.encrypted_login_password:
            raise HTTPException(status_code=404, detail="Credentials are not configured")
        try:
            password = CredentialCipher(
                _secret(request.app.state.settings, "credential_fernet_key")
            ).decrypt(account.encrypted_login_password)
        except Exception as exc:
            logger.exception(
                "admin_credential_decryption_failed", extra={"account_id": account.id}
            )
            raise HTTPException(status_code=503, detail="Credentials are unavailable") from exc
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="credentials.revealed",
                actor=request.app.state.settings.admin_username,
            )
        )
        await session.commit()
        return {"email": account.login_email, "password": password}

    @app.get("/admin/accounts/{account_id}/capability")
    async def reveal_admin_capability(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        settings: Settings = request.app.state.settings
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        if not account.encrypted_access_token:
            raise HTTPException(
                status_code=404,
                detail="Rotate this legacy link before it can be displayed",
            )
        if not _active_until(account.capability_expires_at):
            raise HTTPException(status_code=410, detail="Link has expired; rotate it")
        try:
            token = CredentialCipher(
                _secret(settings, "credential_fernet_key")
            ).decrypt(account.encrypted_access_token)
        except Exception as exc:
            logger.exception(
                "capability_decryption_failed", extra={"account_id": account.id}
            )
            raise HTTPException(status_code=503, detail="Link is unavailable") from exc
        if not verify_capability_token(
            token,
            account.access_token_hash,
            _secret(settings, "access_token_pepper"),
        ):
            raise HTTPException(status_code=503, detail="Link is unavailable")
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="capability.revealed",
                actor=settings.admin_username,
            )
        )
        await session.commit()
        return {
            "url": _capability_url(settings, account.phone_e164, token),
            "expires_at": account.capability_expires_at,
        }

    @app.post("/admin/accounts/{account_id}/totp")
    async def update_totp(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
        totp_secret: Annotated[str, Form()] = "",
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        try:
            encrypted_seed = _encrypt_totp_input(settings, totp_secret)
        except TotpInputError:
            return await render_admin(
                request,
                session,
                error="Не удалось распознать TOTP. Секрет не изменён.",
                status_code=422,
            )
        if encrypted_seed is None:
            return await render_admin(
                request,
                session,
                error="Введите новый TOTP-секрет.",
                status_code=422,
            )
        account.encrypted_totp_secret = encrypted_seed
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="account.totp.updated",
                actor=settings.admin_username,
            )
        )
        await session.commit()
        return RedirectResponse("/admin?notice=TOTP+updated", status_code=303)

    @app.post("/admin/accounts/{account_id}/totp/remove")
    async def remove_totp(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
        confirmation: Annotated[str, Form(max_length=20)],
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.get(Account, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        if confirmation.strip().upper() != "УДАЛИТЬ":
            return await render_admin(
                request,
                session,
                error="TOTP не удалён: введите слово УДАЛИТЬ.",
                status_code=422,
            )
        account.encrypted_totp_secret = None
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="account.totp.removed",
                actor=settings.admin_username,
            )
        )
        await session.commit()
        return RedirectResponse("/admin?notice=TOTP+removed", status_code=303)

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
        account.encrypted_access_token = CredentialCipher(
            _secret(settings, "credential_fernet_key")
        ).encrypt(token)
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
        if account.wa_logout_command_id is not None:
            return await render_admin(
                request,
                session,
                error="Дождитесь завершения выхода из WhatsApp перед изменением состояния.",
                status_code=409,
            )
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

    @app.post("/admin/accounts/{account_id}/whatsapp/logout")
    async def request_whatsapp_logout(
        account_id: str,
        request: Request,
        _: Annotated[str, Depends(require_admin)],
        session: Annotated[AsyncSession, Depends(get_session)],
        csrf_token: Annotated[str, Form()],
    ):
        settings: Settings = request.app.state.settings
        if not _verify_csrf(settings, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
        account = await session.scalar(
            select(Account).where(Account.id == account_id).with_for_update()
        )
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        if account.wa_logout_command_id is None:
            was_disabled = not account.enabled
            account.enabled = True
            account.wa_logout_command_id = str(uuid4())
            account.wa_state = "logout_requested"
            account.encrypted_qr_data = None
            account.encrypted_pairing_code = None
            account.qr_expires_at = None
            account.last_error = None
            session.add(
                AuditEvent(
                    account_id=account.id,
                    event_type="whatsapp.logout_requested",
                    actor=settings.admin_username,
                    details={"enabled_for_relink": was_disabled},
                )
            )
            await session.commit()
        return RedirectResponse("/admin?notice=WhatsApp+logout+requested", status_code=303)

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
                "label": account.wa_display_name or account.label or "WhatsApp",
                "login_email": account.login_email,
                "has_credentials": bool(
                    account.login_email and account.encrypted_login_password
                ),
                "has_totp": bool(account.encrypted_totp_secret),
                "phone": account.phone_e164,
                "account_created_at": account.created_at,
                "snapshot_url": f"/api/public/{phone_digits}/{token}/snapshot",
                "credentials_url": f"/api/public/{phone_digits}/{token}/credentials",
            },
        )

    @app.get(
        "/api/public/{phone_digits}/{token}/credentials",
        response_model=PublicCredentials,
    )
    async def public_credentials(
        phone_digits: str,
        token: str,
        request: Request,
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        settings: Settings = request.app.state.settings
        await request.app.state.rate_limiter.enforce(
            f"credentials:{phone_digits}:{_client_key(request)}",
            limit=20,
            window_seconds=60,
        )
        account = await _authorized_account(session, settings, phone_digits, token)
        if not account.login_email or not account.encrypted_login_password:
            raise HTTPException(status_code=404, detail="Credentials are not configured")
        try:
            password = CredentialCipher(
                _secret(settings, "credential_fernet_key")
            ).decrypt(account.encrypted_login_password)
        except Exception as exc:
            logger.exception(
                "credential_decryption_failed", extra={"account_id": account.id}
            )
            raise HTTPException(status_code=503, detail="Credentials are unavailable") from exc
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="credentials.revealed",
                actor="capability",
            )
        )
        await session.commit()
        return PublicCredentials(email=account.login_email, password=password)

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
                external_id=item.external_id,
                sender_name=_metadata_text(item.raw_metadata, "push_name"),
                sender_phone=item.sender_e164,
                sender_jid=_metadata_text(item.raw_metadata, "remote_jid"),
                participant_jid=_metadata_text(item.raw_metadata, "participant"),
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
                now = datetime.now(UTC)
                public_totp = PublicTotp(
                    code=totp_code(seed, for_time=now),
                    valid_for=totp_seconds_remaining(for_time=now),
                    period=DEFAULT_INTERVAL,
                    server_time=now,
                    valid_until=totp_valid_until(for_time=now),
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
        if account.wa_logout_command_id is not None:
            return {"ok": True, "ignored": True, "reason": "logout_pending"}
        if not account.enabled:
            account.wa_state = "disabled"
            account.encrypted_qr_data = None
            account.encrypted_pairing_code = None
            account.qr_expires_at = None
            await session.commit()
            return {"ok": True, "ignored": True}
        old_state = account.wa_state
        account.wa_state = payload.state
        if payload.account_name is not None:
            account.wa_display_name = payload.account_name.strip()[:120] or None
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
        "/api/internal/accounts/{account_id}/commands/logout/{command_id}/ack",
        dependencies=[Depends(require_internal)],
    )
    async def acknowledge_whatsapp_logout(
        account_id: str,
        command_id: str,
        session: Annotated[AsyncSession, Depends(get_session)],
    ):
        account = await session.scalar(
            select(Account).where(Account.id == account_id).with_for_update()
        )
        if account is None:
            raise HTTPException(status_code=404, detail="Account not found")
        expected = account.wa_logout_command_id or ""
        if len(command_id) != 36 or not secrets.compare_digest(
            command_id.encode(), expected.encode()
        ):
            return {"ok": True, "ignored": True, "reason": "stale_command"}
        account.wa_logout_command_id = None
        account.wa_state = "logged_out" if account.enabled else "disabled"
        account.encrypted_qr_data = None
        account.encrypted_pairing_code = None
        account.qr_expires_at = None
        account.last_error = None
        session.add(
            AuditEvent(
                account_id=account.id,
                event_type="whatsapp.logout_completed",
                actor="whatsapp-worker",
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
