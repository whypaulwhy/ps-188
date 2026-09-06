"""The initial schema.

The three tables phase 9 introduces: a case record holding one screening
decision, a ledger leaf holding its position in the transparency log, and a
review record holding what an officer decided about it afterwards.

`ledger_leaf` rows are never updated and never deleted. There is no database
constraint that can enforce that — deleting one is a valid SQL statement — so it
is enforced by the application and by the log itself, which stops verifying if
anyone tries. See ADR 0003.

Revision ID: 849836e31578
Revises:
Created: 2026-09-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "849836e31578"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the case, ledger and review tables."""
    op.create_table(
        "case_record",
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("verdict_json", sa.Text(), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=64), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("case_id"),
    )
    op.create_table(
        "ledger_leaf",
        sa.Column("leaf_index", sa.Integer(), nullable=False),
        sa.Column("leaf_hash", sa.String(length=64), nullable=False),
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("verdict_digest", sa.String(length=64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("leaf_index"),
        sa.UniqueConstraint("leaf_hash"),
    )
    with op.batch_alter_table("ledger_leaf", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_ledger_leaf_case_id"), ["case_id"], unique=False)

    op.create_table(
        "review_record",
        sa.Column("review_index", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("system_decision", sa.String(length=16), nullable=False),
        sa.Column("officer_id", sa.String(length=64), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("review_json", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("review_index"),
    )
    with op.batch_alter_table("review_record", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_review_record_case_id"), ["case_id"], unique=False)


def downgrade() -> None:
    """Drop all three tables.

    Downgrading destroys the transparency log, which cannot be rebuilt from
    anything else. It exists because a migration chain without a downgrade
    cannot be tested; it is not an operational procedure.
    """
    with op.batch_alter_table("review_record", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_review_record_case_id"))
    op.drop_table("review_record")

    with op.batch_alter_table("ledger_leaf", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ledger_leaf_case_id"))
    op.drop_table("ledger_leaf")

    op.drop_table("case_record")
