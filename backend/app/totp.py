"""Small, deterministic RFC 6238 TOTP helpers."""

from __future__ import annotations

import hashlib
import time
from base64 import b32decode
from binascii import Error as BinasciiError
from datetime import UTC, datetime
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import pyotp


DEFAULT_INTERVAL = 30
DEFAULT_DIGITS = 6
MIN_SECRET_BYTES = 10
MAX_SECRET_LENGTH = 256


class TotpInputError(ValueError):
    """Raised when an administrator supplies an unsupported TOTP value."""


def _single_query_value(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    if values is None:
        return None
    if len(values) != 1:
        raise TotpInputError(f"TOTP URI contains duplicate {name} parameters")
    return values[0]


def normalize_totp_input(value: str) -> str | None:
    """Return a canonical Base32 seed from Base32 text or an otpauth TOTP URI.

    WhatServ currently stores the seed only, so URI options that would change
    RFC 6238 behaviour are rejected instead of being silently discarded.
    """
    if not isinstance(value, str):
        raise TotpInputError("TOTP value must be text")
    raw = value.strip()
    if not raw:
        return None

    secret = raw
    if raw.lower().startswith("otpauth://"):
        parsed = urlsplit(raw)
        if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp":
            raise TotpInputError("Only otpauth://totp links are supported")
        query = parse_qs(parsed.query, keep_blank_values=True)
        secret = _single_query_value(query, "secret") or ""
        algorithm = (_single_query_value(query, "algorithm") or "SHA1").upper()
        digits = _single_query_value(query, "digits") or str(DEFAULT_DIGITS)
        period = _single_query_value(query, "period") or str(DEFAULT_INTERVAL)
        if algorithm != "SHA1" or digits != str(DEFAULT_DIGITS) or period != str(DEFAULT_INTERVAL):
            raise TotpInputError("TOTP must use SHA1, 6 digits and a 30-second period")

    normalized = "".join(secret.split()).upper().rstrip("=")
    if not normalized:
        raise TotpInputError("TOTP secret is missing")
    if len(normalized) > MAX_SECRET_LENGTH:
        raise TotpInputError("TOTP secret is too long")
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in normalized):
        raise TotpInputError("TOTP secret must be Base32")

    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        decoded = b32decode(normalized + padding, casefold=False)
    except (BinasciiError, ValueError) as exc:
        raise TotpInputError("TOTP secret must be valid Base32") from exc
    if len(decoded) < MIN_SECRET_BYTES:
        raise TotpInputError("TOTP secret is too short")

    try:
        totp_code(normalized, for_time=0)
    except Exception as exc:
        raise TotpInputError("TOTP secret is invalid") from exc
    return normalized


def verify_totp_code(
    seed: str,
    code: str,
    *,
    for_time: int | float | datetime | None = None,
    valid_window: int = 1,
    clock: Callable[[], float] = time.time,
) -> bool:
    """Verify a supplied current code without ever including it in errors."""
    normalized_code = "".join(code.split()) if isinstance(code, str) else ""
    if len(normalized_code) != DEFAULT_DIGITS or not normalized_code.isdigit():
        return False
    timestamp = _timestamp(for_time, clock)
    return bool(
        pyotp.TOTP(seed, interval=DEFAULT_INTERVAL, digits=DEFAULT_DIGITS).verify(
            normalized_code,
            for_time=timestamp,
            valid_window=valid_window,
        )
    )


def _timestamp(for_time: int | float | datetime | None, clock: Callable[[], float]) -> int:
    if for_time is None:
        return int(clock())
    if isinstance(for_time, datetime):
        return int(for_time.timestamp())
    return int(for_time)


def totp_code(
    seed: str,
    *,
    for_time: int | float | datetime | None = None,
    interval: int = DEFAULT_INTERVAL,
    digits: int = DEFAULT_DIGITS,
    digest: Callable = hashlib.sha1,
    clock: Callable[[], float] = time.time,
) -> str:
    """Calculate a TOTP code at an injectable point in time."""
    if not isinstance(seed, str) or not seed.strip():
        raise ValueError("TOTP seed is required")
    if interval <= 0 or digits <= 0:
        raise ValueError("TOTP interval and digits must be positive")
    return pyotp.TOTP(seed, interval=interval, digits=digits, digest=digest).at(
        _timestamp(for_time, clock)
    )


def totp_seconds_remaining(
    *,
    for_time: int | float | datetime | None = None,
    interval: int = DEFAULT_INTERVAL,
    clock: Callable[[], float] = time.time,
) -> int:
    """Return seconds left in the current TOTP period (1 through interval)."""
    if interval <= 0:
        raise ValueError("TOTP interval must be positive")
    timestamp = _timestamp(for_time, clock)
    return interval - (timestamp % interval)


def totp_valid_until(
    *,
    for_time: int | float | datetime | None = None,
    interval: int = DEFAULT_INTERVAL,
    clock: Callable[[], float] = time.time,
) -> datetime:
    """Return the exact UTC boundary at which the current code expires."""
    if interval <= 0:
        raise ValueError("TOTP interval must be positive")
    timestamp = _timestamp(for_time, clock)
    boundary = ((timestamp // interval) + 1) * interval
    return datetime.fromtimestamp(boundary, tz=UTC)
