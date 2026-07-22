"""Make phone optional, non-unique account metadata.

Revision ID: 0003_phone_metadata
Revises: 0002_logout_command
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_phone_metadata"
down_revision = "0002_logout_command"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_accounts_phone_e164", table_name="accounts")
    op.drop_constraint("accounts_phone_e164_key", "accounts", type_="unique")
    op.alter_column(
        "accounts",
        "phone_e164",
        existing_type=sa.String(length=16),
        type_=sa.String(length=120),
        nullable=True,
    )
    op.create_index(
        "ix_accounts_phone_e164",
        "accounts",
        ["phone_e164"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_accounts_phone_e164", table_name="accounts")
    op.alter_column(
        "accounts",
        "phone_e164",
        existing_type=sa.String(length=120),
        type_=sa.String(length=16),
        nullable=False,
    )
    op.create_unique_constraint(
        "accounts_phone_e164_key",
        "accounts",
        ["phone_e164"],
    )
    op.create_index(
        "ix_accounts_phone_e164",
        "accounts",
        ["phone_e164"],
        unique=True,
    )
