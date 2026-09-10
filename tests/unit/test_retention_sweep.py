"""Retention, enforced against a real database rather than argued about.

`core/privacy/retention.py` has decided what may be kept since phase 3. Nothing
acted on it, so a deployment kept everything. These tests are the criterion for
the enforcement: a case past its window is destroyed, a case inside its window
is not, the ledger survives both, and a destroyed case is distinguishable from
one that never existed.

**The most important test in this file is `test_the_ledger_still_verifies`.**
Destroying a case must not weaken the audit trail; if it did, retention and the
transparency log would be in direct conflict and one of them would have to be
abandoned. ADR 0006 is the resolution, and this is where it is checked.
"""

from __future__ import annotations

import datetime
import pathlib
from typing import Final

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.contracts import Decision, OfficerReview, Result, Rung
from core.privacy.retention import ArtefactCategory, RetentionPolicy
from core.trust.ladder import resolve
from db.models import CaseRecord, DestructionRow, LedgerLeaf, ReviewRecord
from db.recording import load_case, load_destruction, load_log, record_review, record_screening
from db.retention import due_cases, plan_destruction, sweep
from db.session import create_session_factory
from ledger.hashchain import verify_inclusion
from tests.support import DECIDED_AT, evidence, provenance

WRITTEN_AT: Final[datetime.datetime] = datetime.datetime(2026, 1, 1, 9, 0, tzinfo=datetime.UTC)
"""When the cases in these tests were recorded."""

WINDOW: Final[datetime.timedelta] = datetime.timedelta(days=30)
"""The case-record window these tests apply."""

INSIDE: Final[datetime.datetime] = WRITTEN_AT + datetime.timedelta(days=29)
"""An instant at which nothing is yet due."""

PAST: Final[datetime.datetime] = WRITTEN_AT + datetime.timedelta(days=31)
"""An instant by which the window has closed."""


@pytest.fixture
def factory(tmp_path: pathlib.Path) -> sessionmaker[Session]:
    """Return a guarded session factory over an empty database on disk."""
    return create_session_factory(
        f"sqlite+pysqlite:///{(tmp_path / 'sentinel.db').as_posix()}", create=True
    )


@pytest.fixture
def policy() -> RetentionPolicy:
    """Return a complete policy. It will not construct unless every category is answered."""
    return RetentionPolicy(
        windows={
            ArtefactCategory.FACE_EMBEDDING: datetime.timedelta(days=7),
            ArtefactCategory.PORTRAIT_CROP: datetime.timedelta(days=7),
            ArtefactCategory.DOCUMENT_IMAGE: datetime.timedelta(days=14),
            ArtefactCategory.EVIDENCE_EXHIBIT: datetime.timedelta(days=14),
            ArtefactCategory.CASE_RECORD: WINDOW,
            ArtefactCategory.LEDGER_ENTRY: datetime.timedelta(days=3650),
        }
    )


def screen_one(session: Session, case_id: str, *, at: datetime.datetime) -> None:
    """Record one ordinary screening, so there is something real to destroy."""
    verdict = resolve(
        [evidence(Rung.DETERMINISTIC, Result.PASS)],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )
    record_screening(
        session,
        case_id=case_id,
        verdict=verdict,
        checkpoint_id="ssb-demo-01",
        recorded_at=at,
    )


# What is due, and what is not


def test_a_case_inside_its_window_is_not_due(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The safe direction. Destroying early destroys evidence somebody needs."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)

        assert due_cases(session, policy=policy, now=INSIDE) == ()


def test_a_case_past_its_window_is_due(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The criterion. A record kept beyond its window is the gap this closes."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)

        due = due_cases(session, policy=policy, now=PAST)

    assert [record.case_id for record in due] == ["case-0001"]


def test_due_cases_come_back_oldest_first(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """A sweep interrupted part way through must have cleared the worst overdue."""
    with factory() as session:
        screen_one(session, "newer", at=WRITTEN_AT + datetime.timedelta(days=1))
        screen_one(session, "older", at=WRITTEN_AT)

        due = due_cases(session, policy=policy, now=PAST + datetime.timedelta(days=1))

    assert [record.case_id for record in due] == ["older", "newer"]


# The sweep


def test_the_sweep_destroys_a_case_that_is_due(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The case row is gone afterwards. Not masked, not flagged: gone."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        result = sweep(session, policy=policy, now=PAST)

    assert result.destroyed == ("case-0001",)
    assert result.anything_happened is True

    with factory() as session:
        assert session.get(CaseRecord, "case-0001") is None


def test_the_sweep_leaves_a_case_inside_its_window_alone(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """A sweep that destroys nothing is the ordinary result, not a failure."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        result = sweep(session, policy=policy, now=INSIDE)

        assert result.examined == 1
        assert result.destroyed == ()
        assert result.anything_happened is False
        assert session.get(CaseRecord, "case-0001") is not None


def test_a_dry_run_destroys_nothing(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """An operator must be able to see the answer before it is irreversible."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        result = sweep(session, policy=policy, now=PAST, dry_run=True)

        assert result.destroyed == ("case-0001",)
        assert session.get(CaseRecord, "case-0001") is not None
        assert session.get(DestructionRow, "case-0001") is None


def test_the_sweep_is_idempotent(factory: sessionmaker[Session], policy: RetentionPolicy) -> None:
    """Running it twice must not fail, and must not destroy anything twice."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        sweep(session, policy=policy, now=PAST)
        second = sweep(session, policy=policy, now=PAST)

    assert second.destroyed == ()
    assert second.examined == 0


def test_officer_reviews_are_destroyed_with_their_case(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """A note in an officer's own words belongs to the case and dies with it."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        record_review(
            session,
            OfficerReview(
                case_id="case-0001",
                outcome=Decision.CLEARED,
                officer_id="officer-7",
                note="Bearer known to this post, documents consistent.",
                system_decision=Decision.MANUAL_REVIEW,
                recorded_at=WRITTEN_AT,
            ),
        )
        result = sweep(session, policy=policy, now=PAST)

        assert result.reviews_destroyed == 1
        assert session.execute(select(ReviewRecord)).scalars().all() == []


# What the sweep must never touch


def test_no_ledger_leaf_is_ever_deleted(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """Deleting a leaf breaks the chain for every entry after it. See ADR 0003."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        before = session.execute(select(LedgerLeaf.leaf_hash)).scalars().all()

        sweep(session, policy=policy, now=PAST)

        after = session.execute(select(LedgerLeaf.leaf_hash)).scalars().all()

    assert after[: len(before)] == before, "an existing leaf changed or disappeared"
    assert len(after) == len(before) + 1, "the destruction was not itself logged"


def test_the_ledger_still_verifies_after_a_destruction(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The claim the whole design rests on: retention does not weaken the log.

    Every leaf that existed before the sweep still proves its own inclusion in
    the log afterwards. If this failed, retention and the transparency log would
    be in direct conflict and one would have to be given up.
    """
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        sweep(session, policy=policy, now=PAST)
        log = load_log(session)

    root = log.root()
    for index in range(len(log)):
        assert verify_inclusion(
            log.leaf(index),
            index=index,
            size=len(log),
            proof=log.proof(index),
            root=root,
        ), f"leaf {index} no longer verifies"


def test_the_destruction_is_recorded_in_the_log(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """A silent deletion is indistinguishable from somebody removing a case."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        record = session.get(CaseRecord, "case-0001")
        assert record is not None
        tombstone = plan_destruction(session, record, policy=policy, destroyed_at=PAST)

        sweep(session, policy=policy, now=PAST)
        log = load_log(session)

    assert log.matches_destruction(tombstone, index=len(log) - 1)


# What is left behind


def test_a_destroyed_case_leaves_a_tombstone(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The console needs to say "destroyed", not "no such case"."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        sweep(session, policy=policy, now=PAST)

        tombstone = load_destruction(session, "case-0001")

    assert tombstone is not None
    assert tombstone.case_id == "case-0001"
    assert tombstone.checkpoint_id == "ssb-demo-01"
    assert tombstone.window == WINDOW
    assert tombstone.destroyed_at == PAST


def test_a_case_that_never_existed_has_no_tombstone(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """Never recorded and lawfully destroyed are different, and must read differently."""
    with factory() as session:
        assert load_destruction(session, "case-9999") is None


def test_a_destroyed_case_no_longer_loads(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The verdict is genuinely unreadable afterwards, which is the point."""
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        sweep(session, policy=policy, now=PAST)

        assert load_case(session, "case-0001") is None


def test_the_tombstone_carries_no_decision(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The outcome must not survive the window that was meant to end it.

    Checked against what is actually on disk, not only against the contract:
    a column added later would fail here.
    """
    with factory() as session:
        screen_one(session, "case-0001", at=WRITTEN_AT)
        sweep(session, policy=policy, now=PAST)
        stored = session.get(DestructionRow, "case-0001")
        assert stored is not None
        serialised = stored.destruction_json

    for forbidden in ("CLEARED", "REJECTED", "MANUAL_REVIEW", "verdict"):
        assert forbidden not in serialised, f"{forbidden!r} survived retention"


# Found by audit: neither of these was covered


def test_a_sweep_destroys_every_due_case_not_just_the_first(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """Several cases in one run, which nothing covered until this test.

    Each destruction commits, and SQLAlchemy expires the objects a session
    holds when it does. The remaining `CaseRecord` instances are therefore read
    again mid-loop. That works, and it works by accident unless something says
    so: a sweep that silently destroyed only the first overdue case would leave
    a checkpoint quietly out of compliance with its own policy.
    """
    count = 5
    with factory() as session:
        for index in range(count):
            screen_one(session, f"case-{index}", at=WRITTEN_AT + datetime.timedelta(minutes=index))

        result = sweep(session, policy=policy, now=PAST)

    assert len(result.destroyed) == count
    assert set(result.destroyed) == {f"case-{index}" for index in range(count)}

    with factory() as session:
        assert session.execute(select(CaseRecord)).scalars().all() == []
        for index in range(count):
            assert load_destruction(session, f"case-{index}") is not None


def test_the_ledger_still_verifies_after_many_destructions(
    factory: sessionmaker[Session], policy: RetentionPolicy
) -> None:
    """The audit trail survives a bulk sweep, not only a single one."""
    with factory() as session:
        for index in range(5):
            screen_one(session, f"case-{index}", at=WRITTEN_AT + datetime.timedelta(minutes=index))
        sweep(session, policy=policy, now=PAST)
        log = load_log(session)

    root = log.root()
    for index in range(len(log)):
        assert verify_inclusion(
            log.leaf(index), index=index, size=len(log), proof=log.proof(index), root=root
        ), f"leaf {index} stopped verifying after a bulk destruction"
