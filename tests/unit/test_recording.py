"""Writing a case and its ledger entry together, or writing neither.

The hole this guards against is quiet: a verdict stored with nothing vouching
for it, or a log entry pointing at a record that was never written. Neither
raises anything at the time, and both are found years later by whoever is
trying to defend a decision.

The retry tests drive the index race deterministically rather than with
threads. A race reproduced by timing is a test that passes on a fast machine
and fails in CI at three in the morning, which teaches everyone to re-run it.
"""

from __future__ import annotations

import datetime
import pathlib
from typing import Final

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.contracts import Decision, OfficerReview, Result, Rung, Verdict
from core.standards.verhoeff import verhoeff_digit
from core.trust.ladder import resolve
from db import recording
from db.guards import RawIdentifierError
from db.models import CaseRecord, LedgerLeaf
from db.recording import (
    RecordingError,
    load_case,
    load_log,
    recent_cases,
    record_review,
    record_screening,
)
from db.session import create_session_factory
from tests.support import DECIDED_AT, evidence, provenance

WHEN: Final[datetime.datetime] = datetime.datetime(2026, 9, 7, 11, 0, tzinfo=datetime.UTC)


@pytest.fixture
def factory(tmp_path: pathlib.Path) -> sessionmaker[Session]:
    """Return a guarded session factory over an empty database on disk."""
    return create_session_factory(
        f"sqlite+pysqlite:///{(tmp_path / 'sentinel.db').as_posix()}", create=True
    )


def rejected() -> Verdict:
    """Return a resolved verdict for a document that fails a fixed rule."""
    return resolve(
        [evidence(Rung.DETERMINISTIC, Result.FAIL)], provenance=provenance(), decided_at=DECIDED_AT
    )


def unresolved() -> Verdict:
    """Return a verdict that needs a person to look at it."""
    return resolve(
        [evidence(Rung.INFERENCE, Result.SUSPICIOUS)],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )


def store(factory: sessionmaker[Session], case_id: str, verdict: Verdict) -> int:
    """Record one screening and return its leaf index."""
    with factory() as session:
        return record_screening(
            session, case_id=case_id, verdict=verdict, checkpoint_id="ssb-demo-01", recorded_at=WHEN
        )


def counts(factory: sessionmaker[Session]) -> tuple[int, int]:
    """Return how many cases and how many ledger leaves exist."""
    with factory() as session:
        return (
            session.execute(select(func.count()).select_from(CaseRecord)).scalar_one(),
            session.execute(select(func.count()).select_from(LedgerLeaf)).scalar_one(),
        )


def test_a_screening_writes_both_rows(factory: sessionmaker[Session]) -> None:
    """The ordinary path, so the failures below are failures of something real."""
    assert store(factory, "c1", rejected()) == 0
    assert counts(factory) == (1, 1)


def test_indices_are_assigned_in_order(factory: sessionmaker[Session]) -> None:
    """Positions in the log are what inclusion proofs are computed against."""
    assert [store(factory, f"c{n}", rejected()) for n in range(3)] == [0, 1, 2]


def test_a_duplicate_case_writes_nothing(factory: sessionmaker[Session]) -> None:
    """A rejected write must not leave a ledger entry behind it."""
    store(factory, "c1", rejected())

    with factory() as session, pytest.raises(RecordingError, match="already been recorded"):
        record_screening(
            session, case_id="c1", verdict=rejected(), checkpoint_id="cp", recorded_at=WHEN
        )

    assert counts(factory) == (1, 1)


def test_a_refused_value_writes_nothing(factory: sessionmaker[Session]) -> None:
    """The rule 3 guard fires during the flush, which must take the leaf with it."""
    body = "23456789012"
    review = OfficerReview(
        case_id="c1",
        outcome=Decision.CLEARED,
        officer_id="officer-12",
        note=f"Bearer quoted {body + verhoeff_digit(body)} at the counter.",
        system_decision=Decision.MANUAL_REVIEW,
        recorded_at=WHEN,
    )
    store(factory, "c1", unresolved())

    with factory() as session, pytest.raises(RawIdentifierError):
        record_review(session, review)

    assert counts(factory) == (1, 1)


def test_a_review_does_not_touch_the_verdict(factory: sessionmaker[Session]) -> None:
    """The system's record keeps saying what the checks established. Always."""
    store(factory, "c1", unresolved())
    with factory() as session:
        record_review(
            session,
            OfficerReview(
                case_id="c1",
                outcome=Decision.CLEARED,
                officer_id="officer-12",
                note="Bearer produced a second document and the photograph matches.",
                system_decision=Decision.MANUAL_REVIEW,
                recorded_at=WHEN,
            ),
        )

    with factory() as session:
        view = load_case(session, "c1")

    assert view is not None
    assert view.verdict.decision is Decision.MANUAL_REVIEW
    assert view.standing_decision is Decision.CLEARED
    assert not view.awaiting_review


def test_a_case_nobody_has_looked_at_is_awaiting_review(factory: sessionmaker[Session]) -> None:
    """What puts a case on the queue's first list."""
    store(factory, "c1", unresolved())

    with factory() as session:
        view = load_case(session, "c1")

    assert view is not None
    assert view.awaiting_review
    assert view.standing_decision is Decision.MANUAL_REVIEW


def test_a_rejected_case_is_not_awaiting_review(factory: sessionmaker[Session]) -> None:
    """A hard failure is decided. It is not work sitting in a queue."""
    store(factory, "c1", rejected())

    with factory() as session:
        view = load_case(session, "c1")

    assert view is not None
    assert not view.awaiting_review


def test_a_second_review_supersedes_the_first(factory: sessionmaker[Session]) -> None:
    """A supervisor revisiting a call is a sequence of records, not an edit."""
    store(factory, "c1", unresolved())
    for outcome, officer in ((Decision.CLEARED, "officer-12"), (Decision.REJECTED, "super-2")):
        with factory() as session:
            record_review(
                session,
                OfficerReview(
                    case_id="c1",
                    outcome=outcome,
                    officer_id=officer,
                    note="Reviewed the document and the bearer's account of it.",
                    system_decision=Decision.MANUAL_REVIEW,
                    recorded_at=WHEN,
                ),
            )

    with factory() as session:
        view = load_case(session, "c1")

    assert view is not None
    assert len(view.reviews) == 2
    assert view.standing_decision is Decision.REJECTED
    assert view.reviews[0].outcome is Decision.CLEARED


def test_an_unknown_case_is_absent_rather_than_empty(factory: sessionmaker[Session]) -> None:
    """None, not a blank case. A blank case would render as one with no findings."""
    with factory() as session:
        assert load_case(session, "no-such-case") is None


def test_the_log_rebuilds_from_storage(factory: sessionmaker[Session]) -> None:
    """A restart must reach the same root, or every published checkpoint breaks."""
    for number in range(4):
        store(factory, f"c{number}", rejected())

    with factory() as session:
        rebuilt = load_log(session)
        again = load_log(session)

    assert len(rebuilt) == 4
    assert rebuilt.root() == again.root()


def test_a_stored_verdict_still_matches_its_ledger_entry(factory: sessionmaker[Session]) -> None:
    """What the database holds is what the log recorded."""
    index = store(factory, "c1", rejected())

    with factory() as session:
        view = load_case(session, "c1")
        log = load_log(session)

    assert view is not None
    assert log.matches(view.verdict, index=index)


def test_a_stored_review_still_matches_its_ledger_entry(factory: sessionmaker[Session]) -> None:
    """The same claim for the second kind of record the log holds."""
    store(factory, "c1", unresolved())
    review = OfficerReview(
        case_id="c1",
        outcome=Decision.CLEARED,
        officer_id="officer-12",
        note="Bearer produced a second document and the photograph matches.",
        system_decision=Decision.MANUAL_REVIEW,
        recorded_at=WHEN,
    )
    with factory() as session:
        index = record_review(session, review)

    with factory() as session:
        view = load_case(session, "c1")
        log = load_log(session)

    assert view is not None
    assert log.matches_review(view.reviews[0], index=index)


def test_recent_cases_are_newest_first(factory: sessionmaker[Session]) -> None:
    """An officer opens the queue to see what just arrived."""
    for number in range(3):
        with factory() as session:
            record_screening(
                session,
                case_id=f"c{number}",
                verdict=unresolved(),
                checkpoint_id="cp",
                recorded_at=WHEN + datetime.timedelta(minutes=number),
            )

    with factory() as session:
        listed = recent_cases(session, limit=2)

    assert [view.case_id for view in listed] == ["c2", "c1"]


def test_a_lost_race_for_an_index_is_retried(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two screenings can read the same next index. One must not take the other's.

    Driven deterministically: the first read returns a position already taken,
    as it would if another writer had committed in between.
    """
    store(factory, "c1", rejected())
    reads = iter([0, 1])
    monkeypatch.setattr(recording, "_next_leaf_index", lambda _session: next(reads))

    assert store(factory, "c2", rejected()) == 1
    assert counts(factory) == (2, 2)


def test_repeated_collisions_are_reported_rather_than_looped(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry that never succeeds must stop and say so, not spin."""
    store(factory, "c1", rejected())
    monkeypatch.setattr(recording, "_next_leaf_index", lambda _session: 0)

    with factory() as session, pytest.raises(RecordingError, match="after 5 attempts"):
        record_screening(
            session, case_id="c2", verdict=rejected(), checkpoint_id="cp", recorded_at=WHEN
        )

    assert counts(factory) == (1, 1)
