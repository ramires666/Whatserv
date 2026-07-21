"""Application configuration loaded exclusively from environment variables."""

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings.  Secrets intentionally have no development defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = "postgresql+asyncpg://whatserv:whatserv@localhost:5432/whatserv"
    admin_username: str = "admin"
    admin_password: SecretStr
    internal_api_token: SecretStr
    fernet_key: SecretStr = Field(
        description="URL-safe base64 Fernet key used to encrypt TOTP seeds at rest."
    )
    qr_fernet_key: SecretStr = Field(
        description="Independent Fernet key used to encrypt short-lived QR payloads."
    )
    credential_fernet_key: SecretStr = Field(
        description="Independent Fernet key used to encrypt login passwords at rest."
    )
    access_token_pepper: SecretStr
    public_base_url: str = "https://localhost:8000"
    allow_insecure_http: bool = False
    capability_ttl_hours: int = Field(default=720, ge=1, le=8760)
    qr_ttl_seconds: int = Field(default=120, ge=30, le=600)
    message_page_size: int = Field(default=100, ge=1, le=500)
    auto_create_schema: bool = False

    @field_validator("admin_password", "internal_api_token", "access_token_pepper")
    @classmethod
    def validate_runtime_secret(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 24 or raw.startswith("CHANGE_ME"):
            raise ValueError("runtime secrets must contain at least 24 non-placeholder characters")
        return value

    @field_validator("public_base_url")
    @classmethod
    def normalize_public_base_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("public_base_url must be an absolute HTTP(S) URL")
        return value

    def model_post_init(self, __context) -> None:
        if self.public_base_url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("HTTP public_base_url requires ALLOW_INSECURE_HTTP=true")

    @field_validator("fernet_key", "qr_fernet_key", "credential_fernet_key")
    @classmethod
    def validate_fernet_key(cls, value: SecretStr) -> SecretStr:
        # Fernet keys are URL-safe base64 encodings of 32 random bytes (44 chars).
        import base64

        try:
            decoded = base64.urlsafe_b64decode(value.get_secret_value().encode("ascii"))
        except Exception as exc:  # pragma: no cover - exact decoder exception is irrelevant
            raise ValueError("fernet_key must be a valid URL-safe base64 Fernet key") from exc
        if len(decoded) != 32:
            raise ValueError("fernet_key must decode to exactly 32 bytes")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
