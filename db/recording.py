"""Writing a case and its ledger entry together, or writing neither.

The audit trail is two rows: the verdict in `case_record`, and its digest in
`ledger_leaf`. If the first is written and the second is not, the case exists
with nothing vouching for it; if the second is written and the first is not,
the log points at a record that was never stored. Both are holes an auditor
would find years later, when nobody remembers which write failed.

So both go in one transaction. That is the whole reason this module exists
rather than the routes calling `session.add` twice.

**On the leaf index.** It is `max + 1` computed inside the transaction, which
two concurrent screenings can read as the same value. The primary key then
rejects the loser, and the write is retried — an append that quietly took
someone else's index would corrupt every inclusion proof after it. SQLite
serialises writers, so this is a narrow window; it is handled rather than
argued about.

**On rebuilding the log.** `load_log` reads every leaf and replays it. That is
linear in the number of cases and is fine for a checkpoint, which sees
thousands of crossings rather than millions. If it ever stops being fine, the
fix is a cached root with a stored tree, not a shortcut that skips verification.
"""

from __future__ import annotations

import dataclasses
import datetime
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.contracts import Decision, OfficerReview, Verdict
from db.guards import RawIdentifierError
from db.models import CaseRecord, LedgerLeaf, ReviewRecord
from ledger.hashchain import leaf_hash
from ledger.interface import (
    LedgerEntry,
    TransparencyLog,
    canonical_review_bytes,
    canonical_verdict_bytes,
)

APPEND_ATTEMPTS: Final[int] = 5
"""How many times an append retries after losing a race for the next index."""


class RecordingError(RuntimeError):
    """A case could not be written, and nothing partial was left behind."""


@dataclasses.dataclass(frozen=True)
class CaseView:
    """One case as the console and the API see it: the verdict, and what followed."""

    case_id: str
    verdict: Verdict
    checkpoint_id: str
    leaf_index: int
    created_at: datetime.datetime
    reviews: tuple[OfficerReview, ...] = ()

    @property
    def standing_decision(self) -> Decision:
        """The decision in force: the latest officer review, or the system's.

        Returns:
            What the case currently amounts to. The system's verdict is never
            rewritten, so this is computed rather than stored — a stored copy is
            a second source of truth, and the two would eventually disagree.
        """
        return self.reviews[-1].outcome if self.reviews else self.verdict.decision

    @property
    def awaiting_review(self) -> bool:
        """Whether a person still has to look at this case."""
        return self.verdict.decision is Decision.MANUAL_REVIEW and not self.reviews


def _next_leaf_index(session: Session) -> int:
    """Return the next position in the log, read inside the caller's transaction."""
    highest = session.execute(select(func.max(LedgerLeaf.leaf_index))).scalar_one_or_none()
    return 0 if highest is None else int(highest) + 1


def _append_leaf(session: Session, entry: LedgerEntry) -> LedgerLeaf:
    """Build the ledger row for an entry at the next free index."""
    return LedgerLeaf(
        leaf_index=_next_leaf_index(session),
        leaf_hash=leaf_hash(entry.canonical_bytes()).hex(),
        case_id=entry.case_id,
        verdict_digest=entry.verdict_digest,
        recorded_at=entry.recorded_at,
    )


def record_screening(
    session: Session,
    *,
    case_id: str,
    verdict: Verdict,
    checkpoint_id: str,
    recorded_at: datetime.datetime,
) -> int:
    """Write one screening and its ledger entry in a single transaction.

    Args:
        session: An open session. It is committed on success and rolled back on
            failure; nothing partial survives either way.
        case_id: Opaque case identifier. Never a document number.
        verdict: The decision to store.
        checkpoint_id: Which crossing decided it.
        recorded_at: When the entry was appended.

    Returns:
        The leaf index of the new ledger entry.

    Raises:
        RecordingError: If the case could not be written — a duplicate case
            identifier, a refused value, or repeated collisions on the next
            index. The transaction is rolled back before this is raised.
    """
    if session.get(CaseRecord, case_id) is not None:
        # Caught here rather than by the primary key, so the retry below stays
        # about index races. A duplicate case is a permanent error, and five
        # attempts at it would report the wrong cause to whoever reads the log.
        msg = f"case {case_id!r} has already been recorded"
        raise RecordingError(msg)

    entry = LedgerEntry(
        case_id=case_id,
        verdict_digest=leaf_hash(canonical_verdict_bytes(verdict)).hex(),
        recorded_at=recorded_at,
    )
    record = CaseRecord(
        case_id=case_id,
        decision=verdict.decision.value,
        verdict_json=verdict.model_dump_json(),
        checkpoint_id=checkpoint_id,
        decided_at=verdict.decided_at,
        created_at=recorded_at,
    )
    return _append_with_retry(session, record, entry)


def record_review(session: Session, review: OfficerReview) -> int:
    """Write one officer review and its ledger entry in a single transaction.

    Args:
        session: An open session, committed or rolled back as above.
        review: The officer's decision.

    Returns:
        The leaf index of the new ledger entry.

    Raises:
        RecordingError: If the review could not be written. The transaction is
            rolled back first.
    """
    entry = LedgerEntry(
        case_id=review.case_id,
        verdict_digest=leaf_hash(canonical_review_bytes(review)).hex(),
        recorded_at=review.recorded_at,
    )
    record = ReviewRecord(
        case_id=review.case_id,
        outcome=review.outcome.value,
        system_decision=review.system_decision.value,
        officer_id=review.officer_id,
        note=review.note,
        review_json=review.model_dump_json(),
        recorded_at=review.recorded_at,
    )
    return _append_with_retry(session, record, entry)


def _append_with_retry(session: Session, record: object, entry: LedgerEntry) -> int:
    """Write a record and its leaf together, retrying a lost race for the index."""
    for attempt in range(APPEND_ATTEMPTS):
        leaf = _append_leaf(session, entry)
        session.add(record)
        session.add(leaf)
        try:
            session.commit()
        except IntegrityError as error:
            session.rollback()
            if attempt == APPEND_ATTEMPTS - 1:
                msg = f"could not append to the ledger after {APPEND_ATTEMPTS} attempts: {error}"
                raise RecordingError(msg) from error
            continue
        except RawIdentifierError:
            # Re-raised unchanged so the caller can tell an officer what to fix.
            # Wrapping it would turn "your note contains a document number" into
            # "the write failed", which nobody can act on.
            session.rollback()
            raise
        except Exception as error:
            session.rollback()
            msg = f"the case was not written, and nothing partial was left behind: {error}"
            raise RecordingError(msg) from error
        return leaf.leaf_index
    msg = "unreachable: the retry loop always returns or raises"
    raise RecordingError(msg)


def load_log(session: Session) -> TransparencyLog:
    """Rebuild the transparency log from storage.

    Args:
        session: An open session.

    Returns:
        The log, in index order. A restart must reach the same root, or every
        published checkpoint would appear broken.
    """
    rows = session.execute(select(LedgerLeaf).order_by(LedgerLeaf.leaf_index)).scalars().all()
    return TransparencyLog(
        [LedgerEntry(row.case_id, row.verdict_digest, row.recorded_at) for row in rows]
    )


def _reviews_for(session: Session, case_id: str) -> tuple[OfficerReview, ...]:
    """Return every review of one case, oldest first."""
    rows = (
        session.execute(
            select(ReviewRecord)
            .where(ReviewRecord.case_id == case_id)
            .order_by(ReviewRecord.review_index)
        )
        .scalars()
        .all()
    )
    return tuple(OfficerReview.model_validate_json(row.review_json) for row in rows)


def load_case(session: Session, case_id: str) -> CaseView | None:
    """Read one case back, with everything that has happened to it.

    Args:
        session: An open session.
        case_id: Which case to read.

    Returns:
        The case, or None if this deployment has no such case.
    """
    record = session.get(CaseRecord, case_id)
    if record is None:
        return None
    leaf = session.execute(
        select(LedgerLeaf).where(LedgerLeaf.case_id == case_id).order_by(LedgerLeaf.leaf_index)
    ).scalar()
    return CaseView(
        case_id=record.case_id,
        verdict=Verdict.model_validate_json(record.verdict_json),
        checkpoint_id=record.checkpoint_id,
        leaf_index=leaf.leaf_index if leaf is not None else -1,
        created_at=record.created_at,
        reviews=_reviews_for(session, case_id),
    )


def recent_cases(session: Session, *, limit: int = 50) -> tuple[CaseView, ...]:
    """Return the most recently written cases, newest first.

    Args:
        session: An open session.
        limit: How many to return.

    Returns:
        The cases. Loaded one at a time rather than by a join, because a case
        without its reviews would be a queue that hides work.
    """
    identifiers = (
        session.execute(
            select(CaseRecord.case_id).order_by(CaseRecord.created_at.desc()).limit(limit)
        )
        .scalars()
        .all()
    )
    loaded = (load_case(session, case_id) for case_id in identifiers)
    return tuple(view for view in loaded if view is not None)
