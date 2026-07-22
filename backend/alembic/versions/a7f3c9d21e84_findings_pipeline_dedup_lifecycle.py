# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""findings pipeline: dedup identity, lifecycle control, evidence + event trails

Adds the finding columns that carry the dedup identity (``rule_id`` / ``location``) and the
report/lifecycle controls (``in_report`` / ``regression_intent``), plus two append-only
child tables: ``finding_evidence`` (extra evidence references kept when dedup collapses the
same issue from more than one adapter) and ``finding_event`` (the audit trail of every
lifecycle transition and in-report toggle). See rules PX-DETERMINISM, PX-HUMAN, PX-EVIDENCE.

Revision ID: a7f3c9d21e84
Revises: b1428574732c
Create Date: 2026-07-22

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a7f3c9d21e84"
down_revision: str | None = "b1428574732c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The lifecycle enum already exists (created with the finding table in the base migration),
# so reference it with create_type=False - re-creating it would fail on PostgreSQL. On SQLite
# this renders as VARCHAR, exactly as the finding.status column does.
FINDING_STATUS = postgresql.ENUM(
    "NEW",
    "TRIAGED",
    "VALIDATED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "FIXED",
    "REGRESSION",
    name="findingstatus",
    create_type=False,
)


def upgrade() -> None:
    """Add the pipeline columns and the two append-only trail tables."""
    with op.batch_alter_table("finding") as batch_op:
        batch_op.add_column(sa.Column("rule_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True))
        batch_op.add_column(
            sa.Column("location", sqlmodel.sql.sqltypes.AutoString(), nullable=True)
        )
        # NOT NULL on an existing table needs a server default to backfill rows; existing
        # findings default to being in-report and not yet flagged for a regression test.
        batch_op.add_column(
            sa.Column("in_report", sa.Boolean(), nullable=False, server_default=sa.true())
        )
        batch_op.add_column(
            sa.Column(
                "regression_intent",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.create_index(op.f("ix_finding_rule_id"), ["rule_id"], unique=False)

    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("source_adapter", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("source_scan_id", sa.Uuid(), nullable=False),
        sa.Column("tool_output", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("matched_rule", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("reproduction_cmd", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("sha256", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
        sa.ForeignKeyConstraint(["source_scan_id"], ["scan.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_evidence_finding_id"), "finding_evidence", ["finding_id"], unique=False
    )
    op.create_index(
        op.f("ix_finding_evidence_source_scan_id"),
        "finding_evidence",
        ["source_scan_id"],
        unique=False,
    )

    op.create_table(
        "finding_event",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("from_status", FINDING_STATUS, nullable=True),
        sa.Column("to_status", FINDING_STATUS, nullable=True),
        sa.Column("in_report", sa.Boolean(), nullable=True),
        sa.Column("actor", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("note", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_event_finding_id"), "finding_event", ["finding_id"], unique=False
    )


def downgrade() -> None:
    """Drop the trail tables and the pipeline columns. The shared findingstatus enum is left
    in place - the finding table still uses it."""
    op.drop_index(op.f("ix_finding_event_finding_id"), table_name="finding_event")
    op.drop_table("finding_event")
    op.drop_index(op.f("ix_finding_evidence_source_scan_id"), table_name="finding_evidence")
    op.drop_index(op.f("ix_finding_evidence_finding_id"), table_name="finding_evidence")
    op.drop_table("finding_evidence")

    with op.batch_alter_table("finding") as batch_op:
        batch_op.drop_index(op.f("ix_finding_rule_id"))
        batch_op.drop_column("regression_intent")
        batch_op.drop_column("in_report")
        batch_op.drop_column("location")
        batch_op.drop_column("rule_id")
