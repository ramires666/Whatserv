"""Small, deterministic RFC 6238 TOTP helpers."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Callable

import pyotp


DEFAULT_INTERVAL = 30
DEFAULT_DIGITS = 6


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
