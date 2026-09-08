"""Retention tombstones.

One table, `destruction_record`. It holds what is left after retention destroys
a case: which case, at which checkpoint, under which window, and how many
officer reviews went with it. No decision and no verdict, deliberately — see
`db.models.DestructionRow` and ADR 0006.

**On the downgrade.** Dropping this table loses the record that destructions
happened at all. The destroyed cases do not come back, and the ledger entries
for those destructions survive, so a downgraded deployment has leaves it cannot
explain. That is recoverable by replaying the log and unpleasant to do, which is
the honest description of a downgrade here.

Revision ID: eee1bbc25ef4
Revises: 849836e31578
Created: 2026-09-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "eee1bbc25ef4"
down_revision: str | None = "849836e31578"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the destruction record table."""
    op.create_table(
        "destruction_record",
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("original_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviews_destroyed", sa.Integer(), nullable=False),
        sa.Column("destruction_json", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("case_id"),
    )


def downgrade() -> None:
    """Drop the destruction record table, losing the account of what was destroyed."""
    op.drop_table("destruction_record")
