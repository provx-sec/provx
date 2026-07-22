# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""authenticated scanning: credential table

Adds the ``credential`` table that holds an engagement's authenticated-scanning credential. The
secret is stored in ``value_encrypted`` (AES-256-GCM, encrypted at the model seam) and is never
returned by any endpoint (rules PX-SECRETS, PX-EVIDENCE). One credential per engagement, enforced
by a unique constraint that mirrors ``Credential.__table_args__``.

Additive and reversible (rule W-03): ``downgrade`` drops the table and its index.

Revision ID: d4b8e2f1c7a6
Revises: c2e6f1a09b53
Create Date: 2026-07-22

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "d4b8e2f1c7a6"
down_revision: str | None = "c2e6f1a09b53"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the credential table, its FK, unique constraint, and lookup index."""
    op.create_table(
        "credential",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("cred_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("header_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("value_encrypted", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("label", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagement.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", name="uq_credential_engagement"),
    )
    op.create_index(
        op.f("ix_credential_engagement_id"), "credential", ["engagement_id"], unique=False
    )


def downgrade() -> None:
    """Drop the credential table and its index."""
    op.drop_index(op.f("ix_credential_engagement_id"), table_name="credential")
    op.drop_table("credential")
