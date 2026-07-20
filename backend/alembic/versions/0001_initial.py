"""Initial WhatServ schema.

Revision ID: 0001_initial
Revises: none
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("phone_e164", sa.String(length=16), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("access_token_hash", sa.String(length=255), nullable=False),
        sa.Column("capability_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("capability_last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("encrypted_totp_secret", sa.Text(), nullable=True),
        sa.Column("wa_state", sa.String(length=40), server_default="new", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("encrypted_qr_data", sa.Text(), nullable=True),
        sa.Column("qr_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("encrypted_pairing_code", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("phone_e164"),
    )
    op.create_index("ix_accounts_phone_e164", "accounts", ["phone_e164"], unique=True)

    op.create_table(
        "messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("account_id", sa.String(length=36), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("sender_e164", sa.String(length=16), nullable=True),
        sa.Column("text", sa.Text(), nullable=True),
        sa.Column("message_type", sa.String(length=64), server_default="text", nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", "external_id", name="uq_messages_account_external_id"),
    )
    op.create_index("ix_messages_account_received_at", "messages", ["account_id", "received_at"])
    op.create_index("ix_messages_received_at", "messages", ["received_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("account_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_account_created", "audit_events", ["account_id", "created_at"])
    op.create_index("ix_audit_events_account_id", "audit_events", ["account_id"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("messages")
    op.drop_table("accounts")
