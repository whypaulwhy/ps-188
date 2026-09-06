"""The phase-3 exit criterion, finally testable: no raw number reaches storage.

The roadmap carried this one forward for six phases, because the criterion names
a persistence path and there was no persistence path to name. There is now, so
this file makes the claim against a real SQLite database rather than against an
argument about types.

**Why the guard has to be hard to remove.** Its value depends entirely on not
producing false alarms: a guard that blocks ordinary writes gets switched off
within a week, and then rule 3 is enforced by nothing. Half of this file is
therefore about what the guard must *allow* — hex digests, fixture numbers,
whole serialised verdicts — and it is the more important half.

**No test here hardcodes an issuable number.** Doing so would put one in the
repository, and `test_no_raw_identifiers.py` would correctly fail. They are
computed at runtime from the Verhoeff digit, which is also a small proof that
the two guards agree about what an issuable number is.
"""

from __future__ import annotations

import datetime
import pathlib
from typing import Final

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session, sessionmaker

from core.contracts import Result, Rung
from core.standards.verhoeff import verhoeff_digit
from core.trust.ladder import resolve
from db.guards import RawIdentifierError, refuse_raw_identifiers
from db.models import CaseRecord, LedgerLeaf
from db.session import create_session_factory
from ledger.interface import canonical_verdict_bytes
from tests.support import DECIDED_AT, evidence, provenance

WRITTEN_AT: Final[datetime.datetime] = datetime.datetime(2026, 9, 7, 9, 0, tzinfo=datetime.UTC)
"""A fixed write time, so rows in these tests are reproducible."""


@pytest.fixture
def factory(tmp_path: pathlib.Path) -> sessionmaker[Session]:
    """Return a guarded session factory over an empty database on disk.

    On disk rather than in memory, because WAL is a property of a file and an
    in-memory database silently reports a different journal mode.
    """
    return create_session_factory(
        f"sqlite+pysqlite:///{(tmp_path / 'sentinel.db').as_posix()}", create=True
    )


def issuable_number() -> str:
    """Return a number with the shape of a real Aadhaar number, computed here.

    Never written down: a literal would be committed to this repository, and the
    scan in `test_no_raw_identifiers.py` would rightly fail on it.
    """
    body = "23456789012"
    return body + verhoeff_digit(body)


def case(**overrides: object) -> CaseRecord:
    """Build a case record with nothing objectionable in it."""
    fields: dict[str, object] = {
        "case_id": "case-0001",
        "decision": "MANUAL_REVIEW",
        "verdict_json": '{"decision":"MANUAL_REVIEW"}',
        "checkpoint_id": "ssb-demo-01",
        "decided_at": DECIDED_AT,
        "created_at": WRITTEN_AT,
    }
    fields.update(overrides)
    return CaseRecord(**fields)


def test_a_case_record_round_trips(factory: sessionmaker[Session]) -> None:
    """The ordinary path works, or nothing below means anything."""
    with factory() as session:
        session.add(case())
        session.commit()

    with factory() as session:
        stored = session.get(CaseRecord, "case-0001")

    assert stored is not None
    assert stored.decision == "MANUAL_REVIEW"


def test_the_database_runs_in_wal_mode(factory: sessionmaker[Session]) -> None:
    """A reader must not block the screening that is writing to the log."""
    with factory() as session:
        mode = session.execute(text("PRAGMA journal_mode")).scalar_one()

    assert mode == "wal"


def test_a_document_number_cannot_be_written(factory: sessionmaker[Session]) -> None:
    """The criterion itself. Rule 3 of CLAUDE.md, enforced at the disk edge."""
    with factory() as session:
        session.add(case(verdict_json=f'{{"number":"{issuable_number()}"}}'))

        with pytest.raises(RawIdentifierError):
            session.commit()


def test_nothing_is_written_when_a_flush_is_refused(factory: sessionmaker[Session]) -> None:
    """A refusal that still wrote the row would be worse than no guard at all."""
    with factory() as session:
        session.add(case(verdict_json=f'{{"number":"{issuable_number()}"}}'))
        with pytest.raises(RawIdentifierError):
            session.commit()

    with factory() as session:
        assert session.execute(select(CaseRecord)).all() == []


def test_the_refusal_does_not_repeat_the_number(factory: sessionmaker[Session]) -> None:
    """A message naming what it caught has leaked it into the log a second time."""
    number = issuable_number()
    with factory() as session:
        session.add(case(verdict_json=f'{{"number":"{number}"}}'))

        with pytest.raises(RawIdentifierError) as caught:
            session.commit()

    assert number not in str(caught.value)
    assert "case_record.verdict_json" in str(caught.value)


def test_every_column_is_checked_not_just_the_expected_one(
    factory: sessionmaker[Session],
) -> None:
    """A number smuggled into an identifier column is still a stored number."""
    with factory() as session:
        session.add(case(case_id=issuable_number()))

        with pytest.raises(RawIdentifierError):
            session.commit()


def test_every_table_is_checked(factory: sessionmaker[Session]) -> None:
    """The guard is attached to the session, so a new table is covered on arrival."""
    with factory() as session:
        session.add(
            LedgerLeaf(
                leaf_index=0,
                leaf_hash="a" * 64,
                case_id=issuable_number(),
                verdict_digest="b" * 64,
                recorded_at=WRITTEN_AT,
            )
        )

        with pytest.raises(RawIdentifierError):
            session.commit()


def test_an_update_is_checked_as_well_as_an_insert(factory: sessionmaker[Session]) -> None:
    """A clean row edited into a dirty one is the obvious way past an insert guard."""
    with factory() as session:
        session.add(case())
        session.commit()

        stored = session.get(CaseRecord, "case-0001")
        assert stored is not None
        stored.verdict_json = f'{{"number":"{issuable_number()}"}}'

        with pytest.raises(RawIdentifierError):
            session.commit()


def test_a_hex_digest_is_not_mistaken_for_a_number(factory: sessionmaker[Session]) -> None:
    """Digests are what this system stores instead of numbers.

    A SHA-256 value routinely contains twelve consecutive digits. If the guard
    tripped on those it would block every row the system writes.
    """
    digest = "3f2a9b" + "1" * 12 + "c" + "0" * 45
    with factory() as session:
        session.add(case(verdict_json=f'{{"digest":"{digest}"}}'))
        session.commit()

    assert len(digest) == 64


def test_a_real_verdict_can_be_stored(factory: sessionmaker[Session]) -> None:
    """The thing actually written in production, put through the guard.

    This is the false-alarm test that matters: an entire serialised verdict,
    full of digests and timestamps, must pass without argument.
    """
    verdict = resolve(
        [
            evidence(Rung.DETERMINISTIC, Result.FAIL),
            evidence(Rung.CRYPTOGRAPHIC, Result.NO_PROOF_PRESENT),
            evidence(Rung.INFERENCE, Result.SUSPICIOUS),
        ],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )

    with factory() as session:
        session.add(
            case(verdict_json=canonical_verdict_bytes(verdict).decode(), decision="REJECTED")
        )
        session.commit()

    with factory() as session:
        stored = session.get(CaseRecord, "case-0001")

    assert stored is not None
    assert stored.decision == "REJECTED"


def test_a_number_that_fails_its_checksum_is_not_blocked(factory: sessionmaker[Session]) -> None:
    """Twelve digits are not an Aadhaar number, and blocking them would be noise."""
    body = "23456789012"
    wrong = body + str((int(verhoeff_digit(body)) + 1) % 10)
    with factory() as session:
        session.add(case(verdict_json=f'{{"reference":"{wrong}"}}'))
        session.commit()

    with factory() as session:
        assert session.get(CaseRecord, "case-0001") is not None


def test_a_number_uidai_never_issues_is_not_blocked(factory: sessionmaker[Session]) -> None:
    """The phase-1 fixtures start with 0 for exactly this reason."""
    body = "01234567890"
    with factory() as session:
        session.add(case(verdict_json=f'{{"fixture":"{body + verhoeff_digit(body)}"}}'))
        session.commit()

    with factory() as session:
        assert session.get(CaseRecord, "case-0001") is not None


def test_the_guard_can_be_called_directly(factory: sessionmaker[Session]) -> None:
    """It is a plain function over a session, so it can be used outside the hook."""
    with factory() as session:
        session.add(case())

        refuse_raw_identifiers(session)


def test_a_timestamp_keeps_its_timezone(factory: sessionmaker[Session]) -> None:
    """SQLite drops the offset, and the ledger commits to the offset.

    ``DateTime(timezone=True)`` writes ``+00:00`` and reads back a naive value,
    so a log rebuilt from these rows hashes different bytes and computes a
    different Merkle root. :class:`db.models.UtcDateTime` is what stops that,
    and this is the regression test for it.
    """
    with factory() as session:
        session.add(case())
        session.commit()

    with factory() as session:
        stored = session.get(CaseRecord, "case-0001")

    assert stored is not None
    assert stored.decided_at == DECIDED_AT
    assert stored.decided_at.isoformat() == DECIDED_AT.isoformat()


def test_a_timestamp_from_another_zone_becomes_utc(factory: sessionmaker[Session]) -> None:
    """One representation on disk, so two records of one instant compare equal."""
    local = DECIDED_AT.astimezone(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    with factory() as session:
        session.add(case(decided_at=local))
        session.commit()

    with factory() as session:
        stored = session.get(CaseRecord, "case-0001")

    assert stored is not None
    assert stored.decided_at == local
    assert stored.decided_at.utcoffset() == datetime.timedelta(0)


def test_a_naive_timestamp_is_refused(factory: sessionmaker[Session]) -> None:
    """Assuming an unmarked time is UTC is how a case ends up dated wrongly.

    SQLAlchemy wraps the refusal in a `StatementError`, so that is what a caller
    catches. The reason survives in the message, which is what matters when this
    fires in a log at three in the morning.
    """
    with factory() as session:
        session.add(case(decided_at=datetime.datetime(2026, 1, 1, 12, 0)))  # Naive on purpose.

        with pytest.raises(StatementError, match="timezone") as caught:
            session.commit()

    assert isinstance(caught.value.orig, ValueError)
