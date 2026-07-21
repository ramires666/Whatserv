"""Security primitives used by the HTTP layer.

This module deliberately keeps clear-text TOTP seeds out of persistence and
logs.  Callers should store only the output of :class:`TotpSeedCipher`.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import secrets
from typing import Final

import phonenumbers
from cryptography.fernet import Fernet, InvalidToken


CAPABILITY_TOKEN_BYTES: Final[int] = 32


class PhoneNormalizationError(ValueError):
    """Raised when a phone number cannot be safely represented as E.164."""


class TotpSeedCipherError(ValueError):
    """Raised for invalid cipher configuration or ciphertext.

    It intentionally does not distinguish malformed and unauthentic tokens.
    """


def normalize_phone(phone: str, *, default_region: str | None = None) -> str:
    """Return a validated phone number in canonical E.164 form.

    Numbers without ``+`` require an explicit ``default_region`` so that an
    ambiguous input can never silently be assigned to the wrong account.
    """
    if not isinstance(phone, str) or not phone.strip():
        raise PhoneNormalizationError("phone number is required")

    raw = phone.strip()
    if not raw.startswith("+") and not default_region:
        raise PhoneNormalizationError("international phone number must start with +")

    try:
        parsed = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as exc:
        raise PhoneNormalizationError("invalid phone number") from exc

    if not phonenumbers.is_valid_number(parsed):
        raise PhoneNormalizationError("invalid phone number")

    normalized = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.E164
    )
    if len(normalized) > 16:  # E.164 permits at most 15 digits plus '+'.
        raise PhoneNormalizationError("invalid phone number")
    return normalized


def mask_phone(phone_e164: str) -> str:
    """Mask a normalized phone number while retaining only its last four digits."""
    if not isinstance(phone_e164, str) or not phone_e164:
        return ""
    digits = "".join(character for character in phone_e164 if character.isdigit())
    if not digits:
        return ""
    visible = digits[-4:]
    return "+" + "•" * max(0, len(digits) - len(visible)) + visible


def generate_capability_token(*, token_bytes: int = CAPABILITY_TOKEN_BYTES) -> str:
    """Generate a high-entropy, URL-safe bearer capability token."""
    if token_bytes < 32:
        raise ValueError("capability token must contain at least 32 random bytes")
    return secrets.token_urlsafe(token_bytes)


def hash_capability_token(token: str, pepper: str | bytes = b"") -> str:
    """Return the HMAC-SHA-256 digest used to authenticate a capability token."""
    if not isinstance(token, str) or not token:
        raise ValueError("capability token is required")
    if isinstance(pepper, str):
        pepper = pepper.encode("utf-8")
    if not isinstance(pepper, bytes):
        raise TypeError("capability token pepper must be bytes or text")
    return hmac.new(pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_capability_token(
    token: str, stored_hash: str, pepper: str | bytes = b""
) -> bool:
    """Constant-time verification of a presented capability against its hash."""
    if not isinstance(token, str) or not token or not isinstance(stored_hash, str):
        return False
    candidate = hash_capability_token(token, pepper)
    return hmac.compare_digest(candidate, stored_hash)


class TotpSeedCipher:
    """Authenticated encryption for TOTP seeds using a configured Fernet key."""

    def __init__(self, key: str | bytes) -> None:
        if isinstance(key, str):
            try:
                key = key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise TotpSeedCipherError("invalid TOTP encryption key") from exc
        if not isinstance(key, bytes) or not key:
            raise TotpSeedCipherError("TOTP encryption key is required")
        try:
            # Constructing Fernet verifies the base64 encoding and key length.
            self._fernet = Fernet(key)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise TotpSeedCipherError("invalid TOTP encryption key") from exc

    def encrypt(self, seed: str) -> str:
        """Encrypt a non-empty seed for database storage."""
        if not isinstance(seed, str) or not seed.strip():
            raise TotpSeedCipherError("TOTP seed is required")
        return self._fernet.encrypt(seed.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str | bytes) -> str:
        """Decrypt a seed or fail closed without exposing crypto details."""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode("ascii")
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise TotpSeedCipherError("invalid encrypted TOTP seed")
        try:
            seed = self._fernet.decrypt(ciphertext).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError, TypeError) as exc:
            raise TotpSeedCipherError("invalid encrypted TOTP seed") from exc
        if not seed.strip():
            raise TotpSeedCipherError("invalid encrypted TOTP seed")
        return seed


class CredentialCipherError(ValueError):
    """Raised without exposing credential plaintext or cryptographic details."""


class CredentialCipher:
    """Authenticated encryption for login passwords stored at rest."""

    def __init__(self, key: str | bytes) -> None:
        if isinstance(key, str):
            try:
                key = key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise CredentialCipherError("invalid credential encryption key") from exc
        if not isinstance(key, bytes) or not key:
            raise CredentialCipherError("credential encryption key is required")
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise CredentialCipherError("invalid credential encryption key") from exc

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str) or not plaintext:
            raise CredentialCipherError("credential value is required")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str | bytes) -> str:
        if isinstance(ciphertext, str):
            try:
                ciphertext = ciphertext.encode("ascii")
            except UnicodeEncodeError as exc:
                raise CredentialCipherError("invalid encrypted credential") from exc
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise CredentialCipherError("invalid encrypted credential")
        try:
            plaintext = self._fernet.decrypt(ciphertext).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError, TypeError) as exc:
            raise CredentialCipherError("invalid encrypted credential") from exc
        if not plaintext:
            raise CredentialCipherError("invalid encrypted credential")
        return plaintext
