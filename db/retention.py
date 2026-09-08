"""Applying the retention policy to what is actually stored.

`core.privacy.retention` decides what may be kept and for how long. Nothing
acted on it, so a deployment kept everything forever and the policy was a
decision nobody had enforced. This module is what enforces it.

**What it destroys.** A case whose `created_at` is older than the
`CASE_RECORD` window, together with every officer review of that case. A review
carries a named officer and a note in their own words; it belongs to the case
and has no meaning without it, so it goes at the same time.

**What it never touches.** `ledger_leaf`. Deleting a leaf breaks the Merkle
chain for every entry appended after it, and every checkpoint ever published
would stop verifying with nothing to point at. The log keeps a digest, not a
verdict, precisely so that this module can exist; see ADR 0006.

**What it leaves behind.** A tombstone, and a new leaf recording the
destruction. An officer following a link to a destroyed case is told it was
destroyed under retention, rather than being shown "no such case" — which would
be indistinguishable from a case that never existed, or from one somebody
removed.

**Why there is no scheduler here.** This is a function and a command, not a
daemon. What runs it, and how often, is a deployment decision: a `cron` entry, a
`systemd` timer, a scheduled task. A background thread inside the API would
delete records on a timer nobody configured and nobody can see, which is a worse
failure than the gap it closes.

The writing itself lives in `db.recording`, which owns every "record and its
ledger entry, together or not at all" transaction in this system. This module
decides *what* is due; that one makes it happen atomically.
"""

from __future__ import annotations

import dataclasses
import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.contracts import DestructionRecord
from core.privacy.retention import ArtefactCategory, RetentionPolicy, is_due_for_deletion
from db.models import CaseRecord, ReviewRecord
from db.recording import record_destruction


@dataclasses.dataclass(frozen=True)
class SweepResult:
    """What one run of the sweep did, for the operator and for the record."""

    examined: int
    """How many case records were considered."""

    destroyed: tuple[str, ...] = ()
    """The case identifiers destroyed, in the order they were destroyed."""

    reviews_destroyed: int = 0
    """How many officer reviews went with them."""

    @property
    def anything_happened(self) -> bool:
        """Whether this run changed anything.

        Returns:
            Whether any case was destroyed. A sweep that destroys nothing is the
            ordinary result and is reported as such rather than as a failure.
        """
        return bool(self.destroyed)


def due_cases(
    session: Session, *, policy: RetentionPolicy, now: datetime.datetime
) -> tuple[CaseRecord, ...]:
    """Return the case records that have outlived their retention window.

    Args:
        session: An open session.
        policy: The deployment's retention policy.
        now: The instant to judge against, passed in so a sweep can be replayed.

    Returns:
        The due cases, oldest first, so that a sweep interrupted part way
        through has destroyed the records that were furthest overdue.
    """
    rows = session.execute(select(CaseRecord).order_by(CaseRecord.created_at)).scalars().all()
    return tuple(
        row
        for row in rows
        if is_due_for_deletion(
            row.created_at,
            category=ArtefactCategory.CASE_RECORD,
            policy=policy,
            now=now,
        )
    )


def plan_destruction(
    session: Session,
    record: CaseRecord,
    *,
    policy: RetentionPolicy,
    destroyed_at: datetime.datetime,
) -> DestructionRecord:
    """Describe what destroying one case would record, without destroying it.

    Separated from the write so that the tombstone can be inspected and tested
    on its own, and so a dry run can show an operator exactly what a sweep would
    do before it does it.

    Args:
        session: An open session, used only to count the reviews attached.
        record: The case that would be destroyed.
        policy: The policy requiring it. Its window is copied onto the
            tombstone, because a policy changed later must not be able to make a
            past destruction look early or late.
        destroyed_at: When the destruction would happen.

    Returns:
        The tombstone that would be written.
    """
    reviews = (
        session.execute(
            select(ReviewRecord.review_index).where(ReviewRecord.case_id == record.case_id)
        )
        .scalars()
        .all()
    )
    return DestructionRecord(
        case_id=record.case_id,
        checkpoint_id=record.checkpoint_id,
        category=ArtefactCategory.CASE_RECORD,
        window=policy.windows[ArtefactCategory.CASE_RECORD],
        original_created_at=record.created_at,
        destroyed_at=destroyed_at,
        reviews_destroyed=len(reviews),
    )


def sweep(
    session: Session,
    *,
    policy: RetentionPolicy,
    now: datetime.datetime,
    dry_run: bool = False,
) -> SweepResult:
    """Destroy every case that has outlived its retention window.

    Each case is destroyed in its own transaction, so a failure part way through
    leaves the cases already destroyed properly destroyed and properly logged,
    rather than rolling back work that would have to be repeated.

    Args:
        session: An open session.
        policy: The deployment's retention policy.
        now: The instant to judge against.
        dry_run: Report what would be destroyed and destroy nothing. An
            operator running this for the first time against real records
            should be able to see the answer before it is irreversible.

    Returns:
        What the run did, or would have done.

    Raises:
        RecordingError: If a destruction could not be written. Cases destroyed
            before the failure stay destroyed, which is why the sweep is safe to
            simply run again.
    """
    examined = len(session.execute(select(CaseRecord.case_id)).scalars().all())
    due = due_cases(session, policy=policy, now=now)

    destroyed: list[str] = []
    reviews = 0
    for record in due:
        tombstone = plan_destruction(session, record, policy=policy, destroyed_at=now)
        if not dry_run:
            record_destruction(session, tombstone)
        destroyed.append(tombstone.case_id)
        reviews += tombstone.reviews_destroyed
    return SweepResult(
        examined=examined,
        destroyed=tuple(destroyed),
        reviews_destroyed=reviews,
    )
