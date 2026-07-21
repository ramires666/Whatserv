"""Pydantic request/response contracts. Secrets never appear in responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AccountCreate(BaseModel):
    phone_e164: str = Field(pattern=r"^\+[1-9]\d{7,14}$")
    label: str | None = Field(default=None, max_length=120)
    access_token: str = Field(min_length=32, max_length=512)
    totp_secret: str | None = Field(default=None, min_length=16, max_length=2048)


class AccountUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=120)
    enabled: bool | None = None
    access_token: str | None = Field(default=None, min_length=32, max_length=512)
    totp_secret: str | None = Field(default=None, min_length=16, max_length=2048)


class AccountRead(ORMModel):
    id: str
    phone_e164: str
    label: str | None
    enabled: bool
    wa_state: str
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class MessageRead(ORMModel):
    id: str
    account_id: str
    external_id: str
    sender_e164: str | None
    text: str | None
    message_type: str
    received_at: datetime
    raw_metadata: dict[str, Any] | None


class MessageList(ORMModel):
    items: list[MessageRead]
    total: int


class TOTPRead(BaseModel):
    phone_e164: str
    code: str = Field(pattern=r"^\d{6,8}$")
    valid_until: datetime


class AuditEventRead(ORMModel):
    id: str
    account_id: str | None
    event_type: str
    actor: str | None
    details: dict[str, Any] | None
    created_at: datetime


class WorkerAccount(ORMModel):
    id: str
    phone_e164: str
    enabled: bool
    wa_state: str
    logout_command_id: str | None = Field(validation_alias="wa_logout_command_id")


class WorkerAccountList(BaseModel):
    items: list[WorkerAccount]


class WorkerStateUpdate(BaseModel):
    state: str = Field(max_length=40)
    account_name: str | None = Field(default=None, max_length=120)
    qr_code: str | None = Field(default=None, max_length=4096)
    pairing_code: str | None = Field(default=None, max_length=32)
    last_error: str | None = Field(default=None, max_length=1000)


class IncomingMessage(BaseModel):
    account_id: str = Field(min_length=1, max_length=36)
    external_id: str = Field(min_length=1, max_length=255)
    sender_phone: str | None = Field(default=None, max_length=64)
    body: str | None = Field(default=None, max_length=100_000)
    received_at: datetime
    message_type: str = Field(default="unknown", max_length=64)
    raw_metadata: dict[str, Any] | None = None


class PublicMessage(BaseModel):
    id: str
    external_id: str
    sender_name: str | None
    sender_phone: str | None
    sender_jid: str | None
    participant_jid: str | None
    body: str | None
    received_at: datetime
    message_type: str


class PublicTotp(BaseModel):
    code: str
    valid_for: int
    period: int = 30
    server_time: datetime
    valid_until: datetime


class PublicCredentials(BaseModel):
    email: str
    password: str


class PublicSnapshot(BaseModel):
    whatsapp_state: str
    messages: list[PublicMessage]
    totp: PublicTotp | None
