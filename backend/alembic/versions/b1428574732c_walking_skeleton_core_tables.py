# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""walking skeleton core tables

Creates the engagement / target / scan / finding tables the walking skeleton persists to.

Revision ID: b1428574732c
Revises:
Create Date: 2026-07-19

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "b1428574732c"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Named enum types are created implicitly with the finding table but are not dropped with
# it on PostgreSQL, so downgrade removes them explicitly to stay reversible (rule W-03).
ENUM_TYPES = ("module", "severity", "confidence", "findingstatus")


def upgrade() -> None:
    """Create the core tables."""
    op.create_table(
        "engagement",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("scope_allow", sa.JSON(), nullable=True),
        sa.Column("scope_deny", sa.JSON(), nullable=True),
        sa.Column("mode", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_engagement_name"), "engagement", ["name"], unique=False)

    op.create_table(
        "scan",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("adapter", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("targets_scanned", sa.Integer(), nullable=False),
        sa.Column("targets_skipped_out_of_scope", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagement.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_engagement_id"), "scan", ["engagement_id"], unique=False)

    op.create_table(
        "target",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagement.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_target_engagement_id"), "target", ["engagement_id"], unique=False)

    op.create_table(
        "finding",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("display_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("target", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("module", sa.Enum("WEB", "API", "INFRA", name="module"), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity"),
            nullable=False,
        ),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column(
            "confidence",
            sa.Enum("HIGH", "MEDIUM", "LOW", name="confidence"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "NEW",
                "TRIAGED",
                "VALIDATED",
                "FALSE_POSITIVE",
                "ACCEPTED_RISK",
                "FIXED",
                "REGRESSION",
                name="findingstatus",
            ),
            nullable=False,
        ),
        sa.Column("attack_techniques", sa.JSON(), nullable=True),
        sa.Column("remediation", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("evidence_tool_output", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("evidence_matched_rule", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("evidence_reproduction_cmd", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("evidence_sha256", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagement.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
        sa.PrimaryKeyConstraint("id"),
        # display_id is a per-engagement sequence (PVX-0001), so it is unique within an
        # engagement, not globally.
        sa.UniqueConstraint("engagement_id", "display_id", name="uq_finding_engagement_display_id"),
    )
    op.create_index(op.f("ix_finding_display_id"), "finding", ["display_id"], unique=False)
    op.create_index(op.f("ix_finding_engagement_id"), "finding", ["engagement_id"], unique=False)
    op.create_index(op.f("ix_finding_scan_id"), "finding", ["scan_id"], unique=False)


def downgrade() -> None:
    """Drop the core tables and the enum types they introduced."""
    op.drop_index(op.f("ix_finding_scan_id"), table_name="finding")
    op.drop_index(op.f("ix_finding_engagement_id"), table_name="finding")
    op.drop_index(op.f("ix_finding_display_id"), table_name="finding")
    op.drop_table("finding")
    op.drop_index(op.f("ix_target_engagement_id"), table_name="target")
    op.drop_table("target")
    op.drop_index(op.f("ix_scan_engagement_id"), table_name="scan")
    op.drop_table("scan")
    op.drop_index(op.f("ix_engagement_name"), table_name="engagement")
    op.drop_table("engagement")

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for enum_name in ENUM_TYPES:
            sa.Enum(name=enum_name).drop(bind, checkfirst=True)
