"""Add encrypted account credentials and durable WhatsApp logout commands.

Revision ID: 0002_logout_command
Revises: 0001_initial
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_logout_command"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "accounts",
        sa.Column("owner_name", sa.String(length=120), nullable=True),
    )
    op.add_column("accounts", sa.Column("comment", sa.Text(), nullable=True))
    op.add_column(
        "accounts",
        sa.Column("login_email", sa.String(length=254), nullable=True),
    )
    op.add_column(
        "accounts",
        sa.Column("encrypted_login_password", sa.Text(), nullable=True),
    )
    op.add_column(
        "accounts",
        sa.Column("encrypted_access_token", sa.Text(), nullable=True),
    )
    op.add_column(
        "accounts",
        sa.Column("wa_display_name", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "accounts",
        sa.Column("wa_logout_command_id", sa.String(length=36), nullable=True),
    )
    op.create_index("ix_accounts_login_email", "accounts", ["login_email"], unique=True)
    op.create_unique_constraint(
        "uq_accounts_wa_logout_command_id",
        "accounts",
        ["wa_logout_command_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_accounts_wa_logout_command_id",
        "accounts",
        type_="unique",
    )
    op.drop_column("accounts", "wa_logout_command_id")
    op.drop_column("accounts", "wa_display_name")
    op.drop_index("ix_accounts_login_email", table_name="accounts")
    op.drop_column("accounts", "encrypted_login_password")
    op.drop_column("accounts", "encrypted_access_token")
    op.drop_column("accounts", "login_email")
    op.drop_column("accounts", "comment")
    op.drop_column("accounts", "owner_name")
