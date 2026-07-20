"""Persistent entities for WhatsApp accounts, inbound messages and audit trail."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.utcnow()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class Account(TimestampMixin, Base):
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    phone_e164: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)
    label: Mapped[str | None] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    access_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    capability_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    capability_last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    encrypted_totp_secret: Mapped[str | None] = mapped_column(Text)
    wa_state: Mapped[str] = mapped_column(String(40), nullable=False, default="new", server_default="new")
    last_error: Mapped[str | None] = mapped_column(Text)
    encrypted_qr_data: Mapped[str | None] = mapped_column(Text)
    qr_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    encrypted_pairing_code: Mapped[str | None] = mapped_column(Text)

    messages: Mapped[list[Message]] = relationship(back_populates="account", cascade="all, delete-orphan")
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="account", passive_deletes=True)


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        UniqueConstraint("account_id", "external_id", name="uq_messages_account_external_id"),
        Index("ix_messages_account_received_at", "account_id", "received_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_e164: Mapped[str | None] = mapped_column(String(16))
    text: Mapped[str | None] = mapped_column(Text)
    message_type: Mapped[str] = mapped_column(String(64), nullable=False, default="text", server_default="text")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    raw_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    account: Mapped[Account] = relationship(back_populates="messages")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_account_created", "account_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    account_id: Mapped[str | None] = mapped_column(ForeignKey("accounts.id", ondelete="SET NULL"), index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    account: Mapped[Account | None] = relationship(back_populates="audit_events")
