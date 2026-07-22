# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""add finding.description for client-ready reports

Adds an optional long-form ``description`` column to ``finding``, distinct from the one-line
``title``. Nullable and unset by current adapters; the HTML report falls back to the title
when it is absent. Additive for report hardening (v0.1).

Revision ID: c2e6f1a09b53
Revises: a7f3c9d21e84
Create Date: 2026-07-22

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "c2e6f1a09b53"
down_revision: str | None = "a7f3c9d21e84"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the nullable description column."""
    with op.batch_alter_table("finding") as batch_op:
        batch_op.add_column(
            sa.Column("description", sqlmodel.sql.sqltypes.AutoString(), nullable=True)
        )


def downgrade() -> None:
    """Drop the description column (rule W-03)."""
    with op.batch_alter_table("finding") as batch_op:
        batch_op.drop_column("description")
