"""What is written to disk, and what is deliberately not.

Two tables. A case record holds a decision and the verdict that justified it; a
ledger leaf holds the transparency log. Neither holds a document number.

**What a case record does not contain.** No raw identifier of any kind. A
document number reaches storage only as a keyed digest produced by
`core.privacy.hashing`, and the guard in :mod:`db.guards` refuses a flush that
would write one anyway. Rule 3 of CLAUDE.md is the reason, and the guard exists
because a rule enforced only by review is a rule that holds until someone is in
a hurry.

**The verdict is stored as its own JSON.** It is the audit record: what was
checked, what was found, what could not be checked, and why. Storing a summary
instead would save space and destroy the ability to answer a challenge years
later.

Retention is not enforced here. A row's age is recorded so that
`core.privacy.retention` can decide, and deletion is the caller's to perform.
"""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, Integer, String, Text, TypeDecorator
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class UtcDateTime(TypeDecorator[datetime.datetime]):
    """A timestamp that keeps its timezone across a round trip through SQLite.

    SQLite has no timestamp type and stores a datetime as text without its
    offset, so ``DateTime(timezone=True)`` writes ``+00:00`` and reads back a
    naive value. The instant survives; the offset does not.

    That is not cosmetic here. The ledger commits to ``isoformat()``, so a log
    rebuilt from these rows after a restart hashes different bytes and computes
    a different Merkle root — every published checkpoint would appear broken,
    with nothing to point at. It was caught by
    ``tests/integration/test_audit_trail.py``, which rebuilds the log from the
    database rather than from memory.

    A naive value is refused on the way in rather than assumed to be UTC.
    Guessing a timezone in an audit record is how a case ends up dated five and
    a half hours away from when it happened.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self, value: datetime.datetime | None, dialect: Dialect
    ) -> datetime.datetime | None:
        """Normalise to UTC on the way in, refusing anything without a timezone."""
        if value is None:
            return None
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = "refusing to store a timestamp with no timezone"
            raise ValueError(msg)
        return value.astimezone(datetime.UTC)

    def process_result_value(
        self, value: datetime.datetime | None, dialect: Dialect
    ) -> datetime.datetime | None:
        """Re-attach UTC on the way out, since that is what was stored."""
        return None if value is None else value.replace(tzinfo=datetime.UTC)


class Base(DeclarativeBase):
    """Declarative base for every table in this deployment."""


class CaseRecord(Base):
    """One screening decision, with the verdict that justified it."""

    __tablename__ = "case_record"

    case_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    """Opaque, per-deployment. Never a document number."""

    decision: Mapped[str] = mapped_column(String(16))
    """`CLEARED`, `MANUAL_REVIEW` or `REJECTED`."""

    verdict_json: Mapped[str] = mapped_column(Text)
    """The full verdict, so a decision can be re-read and defended."""

    checkpoint_id: Mapped[str] = mapped_column(String(64))
    """Which crossing point made the decision."""

    decided_at: Mapped[datetime.datetime] = mapped_column(UtcDateTime())
    """When the ladder resolved the case."""

    created_at: Mapped[datetime.datetime] = mapped_column(UtcDateTime())
    """When the row was written. Retention is measured from here."""


class LedgerLeaf(Base):
    """One entry in the append-only transparency log.

    Rows are never updated and never deleted. Deleting one breaks the Merkle
    chain for every entry after it, which destroys the tamper evidence the log
    exists for; see ADR 0003.
    """

    __tablename__ = "ledger_leaf"

    leaf_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    """Position in the log. Never reused."""

    leaf_hash: Mapped[str] = mapped_column(String(64), unique=True)
    """The leaf hash, hex encoded."""

    case_id: Mapped[str] = mapped_column(String(128), index=True)
    """Which case this entry records."""

    verdict_digest: Mapped[str] = mapped_column(String(64))
    """Digest of the verdict, not the verdict. See `ledger.interface`."""

    recorded_at: Mapped[datetime.datetime] = mapped_column(UtcDateTime())
    """When the entry was appended."""


class ReviewRecord(Base):
    """One officer's decision on one case.

    A row here never replaces a `CaseRecord`. The verdict keeps saying what the
    automated checks established; this says what a person decided about it, and
    both are true at once. See :class:`core.contracts.review.OfficerReview` for
    why that separation is not negotiable.
    """

    __tablename__ = "review_record"

    review_index: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    """Order of review within this deployment. A case may be reviewed twice."""

    case_id: Mapped[str] = mapped_column(String(128), index=True)
    """Which case was reviewed."""

    outcome: Mapped[str] = mapped_column(String(16))
    """What the officer decided: `CLEARED` or `REJECTED`."""

    system_decision: Mapped[str] = mapped_column(String(16))
    """What the system had decided, so an override is visible as one."""

    officer_id: Mapped[str] = mapped_column(String(64))
    """Who decided. An unattributed override is not a review."""

    note: Mapped[str] = mapped_column(Text)
    """Why, in the officer's own words."""

    review_json: Mapped[str] = mapped_column(Text)
    """The full review, so it can be checked against its ledger entry."""

    recorded_at: Mapped[datetime.datetime] = mapped_column(UtcDateTime())
    """When the officer decided."""


def metadata() -> object:
    """Return the SQLAlchemy metadata for all tables.

    Returns:
        The metadata, for schema creation and migrations.
    """
    return Base.metadata
