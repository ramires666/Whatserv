import base64
import hashlib

import pytest
from cryptography.fernet import Fernet

from app.security import (
    CredentialCipher,
    CredentialCipherError,
    PhoneNormalizationError,
    TotpSeedCipher,
    TotpSeedCipherError,
    generate_capability_token,
    hash_capability_token,
    mask_phone,
    normalize_phone,
    verify_capability_token,
)
from app.totp import (
    TotpInputError,
    normalize_totp_input,
    totp_code,
    totp_seconds_remaining,
    totp_valid_until,
    verify_totp_code,
)


def test_normalize_phone_to_e164_and_reject_ambiguous_input():
    assert normalize_phone("+1 (415) 555-2671") == "+14155552671"
    assert normalize_phone("415 555 2671", default_region="US") == "+14155552671"
    with pytest.raises(PhoneNormalizationError):
        normalize_phone("415 555 2671")
    with pytest.raises(PhoneNormalizationError):
        normalize_phone("not-a-number")


def test_phone_mask_only_exposes_last_four_digits():
    assert mask_phone("+14155552671") == "+•••••••2671"
    assert mask_phone("") == ""


def test_capability_token_is_high_entropy_hashed_and_verified():
    token = generate_capability_token()
    assert len(token) >= 43
    digest = hash_capability_token(token)
    assert digest != token
    assert verify_capability_token(token, digest)
    assert not verify_capability_token(token + "x", digest)
    assert not verify_capability_token("", digest)
    with pytest.raises(ValueError):
        generate_capability_token(token_bytes=31)


def test_totp_seed_fernet_round_trip_and_tampering_fails_closed():
    cipher = TotpSeedCipher(Fernet.generate_key())
    encrypted = cipher.encrypt("JBSWY3DPEHPK3PXP")
    assert encrypted != "JBSWY3DPEHPK3PXP"
    assert cipher.decrypt(encrypted) == "JBSWY3DPEHPK3PXP"

    tampered = encrypted[:-1] + ("A" if encrypted[-1] != "A" else "B")
    with pytest.raises(TotpSeedCipherError, match="invalid encrypted TOTP seed"):
        cipher.decrypt(tampered)
    with pytest.raises(TotpSeedCipherError):
        TotpSeedCipher(b"not-a-fernet-key")


def test_login_password_uses_independent_authenticated_encryption():
    cipher = CredentialCipher(Fernet.generate_key())
    password = "correct horse battery staple"
    encrypted = cipher.encrypt(password)
    assert password not in encrypted
    assert cipher.decrypt(encrypted) == password
    with pytest.raises(CredentialCipherError):
        cipher.decrypt(encrypted[:-2] + "AA")


def test_totp_matches_rfc6238_sha1_vector_and_boundary_countdown():
    # RFC 6238 Appendix B: SHA-1, 8 digits, time 59 seconds.
    seed = base64.b32encode(b"12345678901234567890").decode("ascii")
    assert totp_code(seed, for_time=59, digits=8, digest=hashlib.sha1) == "94287082"
    assert totp_seconds_remaining(for_time=59) == 1
    assert totp_seconds_remaining(for_time=60) == 30


def test_totp_uses_injected_clock_and_validates_arguments():
    seed = "JBSWY3DPEHPK3PXP"
    assert totp_code(seed, clock=lambda: 1_700_000_000) == totp_code(seed, for_time=1_700_000_000)
    with pytest.raises(ValueError):
        totp_code(seed, interval=0)
    with pytest.raises(ValueError):
        totp_seconds_remaining(interval=0)


def test_totp_verification_and_exact_expiry_boundary():
    seed = "JBSWY3DPEHPK3PXP"
    code = totp_code(seed, for_time=59)
    assert verify_totp_code(seed, code, for_time=59)
    assert verify_totp_code(seed, "000000", for_time=59) is False
    assert verify_totp_code(seed, "not-code", for_time=59) is False
    assert totp_valid_until(for_time=59).timestamp() == 60
    assert totp_valid_until(for_time=60).timestamp() == 90


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("jbsw y3dp ehpk 3pxp", "JBSWY3DPEHPK3PXP"),
        ("JBSWY3DPEHPK3PXP====", "JBSWY3DPEHPK3PXP"),
        (
            "otpauth://totp/Example:alice%40example.com?"
            "secret=JBSWY3DPEHPK3PXP&issuer=Example",
            "JBSWY3DPEHPK3PXP",
        ),
    ],
)
def test_normalize_totp_input_accepts_base32_and_standard_uri(raw, expected):
    assert normalize_totp_input(raw) == expected


def test_normalize_totp_input_allows_empty_for_explicit_no_totp_flow():
    assert normalize_totp_input("  ") is None


@pytest.mark.parametrize(
    "raw",
    [
        "NOT-BASE32",
        "MZXW6",
        "otpauth://hotp/example?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth://totp/example?issuer=Example",
        "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&digits=8",
        "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&period=60",
        "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
        "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBVGY3TQOJQ",
    ],
)
def test_normalize_totp_input_rejects_invalid_or_unsupported_values(raw):
    with pytest.raises(TotpInputError):
        normalize_totp_input(raw)
