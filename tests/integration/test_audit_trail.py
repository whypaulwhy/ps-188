"""A screening, recorded so that it can be defended years later.

Phase 9's exit criterion is that a decision can be replayed from the ledger.
This is that path, closed end to end: a photograph is screened, the verdict is
written to a database and its digest to a transparency log, the log is signed,
and then everything is reconstructed from storage and checked.

The test that matters most is the last one. An audit trail that only confirms
untouched records is decoration; this one alters a stored verdict the way a
person covering something up would — by quietly deleting a line saying what was
not checked — and shows the ledger refusing to recognise the result.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.contracts import DocumentType, Provenance, Verdict
from core.trust import resolve
from datagen.synthetic_docs import generate_specimen
from db.models import CaseRecord, LedgerLeaf
from db.session import create_session_factory
from detectors.rung1_deterministic import expiry, mrz_checkdigits
from explain.renderer import NOT_CHECKED_HEADING, render_verdict
from extraction.pipeline import build_subject
from ledger.hashchain import verify_checkpoint, verify_inclusion
from ledger.interface import LedgerEntry, TransparencyLog

WHEN = datetime.datetime(2026, 9, 7, 10, 0, tzinfo=datetime.UTC)
"""Fixed, so a replay is a replay and not a second run at a different time."""

SPECIMEN = generate_specimen(seed=1)
"""One synthetic document, screened twice: once live, once as a replay."""

CASE_ID = "integration-0001"


def screen() -> Verdict:
    """Run the specimen through extraction, the detectors and the ladder.

    Called twice with identical input. Anything that differs between the two
    results is something the ledger would have to tolerate, which is why this
    takes no arguments and reads no clock.
    """
    record = Provenance(
        source_id=CASE_ID,
        sha256=hashlib.sha256(SPECIMEN.png).hexdigest(),
        media_type="image/png",
        byte_size=len(SPECIMEN.png),
        captured_at=WHEN,
        received_at=WHEN,
        checkpoint_id="ssb-demo-01",
    )
    subject = build_subject(
        SPECIMEN.png, provenance=record, declared_type=DocumentType.UNRECOGNISED
    )
    evidence = [
        item
        for detector in (mrz_checkdigits.build(), expiry.build())
        if detector.applies_to(subject)
        for item in detector.run(subject)
    ]
    return resolve(evidence, provenance=record, decided_at=WHEN)


@pytest.fixture
def factory(tmp_path: pathlib.Path) -> sessionmaker[Session]:
    """Return a guarded session factory over an empty database on disk."""
    return create_session_factory(
        f"sqlite+pysqlite:///{(tmp_path / 'sentinel.db').as_posix()}", create=True
    )


def commit_case(factory: sessionmaker[Session], verdict: Verdict) -> TransparencyLog:
    """Write one screening to the database and the log, as a deployment would."""
    log = TransparencyLog()
    index = log.record(verdict, case_id=CASE_ID, recorded_at=WHEN)
    entry = log.entries()[index]

    with factory() as session:
        session.add(
            CaseRecord(
                case_id=CASE_ID,
                decision=verdict.decision.value,
                verdict_json=verdict.model_dump_json(),
                checkpoint_id="ssb-demo-01",
                decided_at=verdict.decided_at,
                created_at=WHEN,
            )
        )
        session.add(
            LedgerLeaf(
                leaf_index=index,
                leaf_hash=log.leaf(index).hex(),
                case_id=entry.case_id,
                verdict_digest=entry.verdict_digest,
                recorded_at=entry.recorded_at,
            )
        )
        session.commit()
    return log


def stored_verdict(factory: sessionmaker[Session]) -> Verdict:
    """Read one case back out of the database as a verdict again."""
    with factory() as session:
        row = session.get(CaseRecord, CASE_ID)
    assert row is not None
    return Verdict.model_validate_json(row.verdict_json)


def test_a_screening_is_written_to_both_the_database_and_the_log(
    factory: sessionmaker[Session],
) -> None:
    """The two records are written together, or the audit trail has a hole in it."""
    log = commit_case(factory, screen())

    with factory() as session:
        cases = session.execute(select(CaseRecord)).scalars().all()
        leaves = session.execute(select(LedgerLeaf)).scalars().all()

    assert len(cases) == 1
    assert len(leaves) == 1
    assert leaves[0].verdict_digest == log.entries()[0].verdict_digest


def test_a_verdict_survives_the_round_trip_through_the_database(
    factory: sessionmaker[Session],
) -> None:
    """Storage must not change the record. Every field comes back as it went in."""
    verdict = screen()
    commit_case(factory, verdict)

    assert stored_verdict(factory) == verdict


def test_a_replayed_screening_matches_the_ledger(factory: sessionmaker[Session]) -> None:
    """The exit criterion: run the case again, and the log recognises the result."""
    log = commit_case(factory, screen())

    assert log.matches(screen(), index=0)


def test_the_stored_verdict_matches_the_ledger(factory: sessionmaker[Session]) -> None:
    """The stronger form: what is in the database is what was logged.

    A replay proves the pipeline is deterministic. This proves the database has
    not drifted from the log since, which is the question an auditor asks.
    """
    log = commit_case(factory, screen())

    assert log.matches(stored_verdict(factory), index=0)


def test_deleting_a_line_about_what_was_not_checked_breaks_the_match(
    factory: sessionmaker[Session],
) -> None:
    """The tamper this whole phase exists to catch.

    Silence about a missing check is exactly what someone would edit out later:
    it makes a case look cleaner without changing the decision. The ledger holds
    a digest of the whole verdict, so the edit is detected even though the
    decision itself is untouched.
    """
    verdict = screen()
    log = commit_case(factory, verdict)
    assert verdict.not_checked, "the specimen must leave something unchecked"

    body = json.loads(verdict.model_dump_json())
    body["not_checked"] = body["not_checked"][:-1]
    altered = Verdict.model_validate(body)

    assert altered.decision is verdict.decision
    assert not log.matches(altered, index=0)


def test_the_log_rebuilds_from_the_database(factory: sessionmaker[Session]) -> None:
    """A restart must reach the same root, or every published checkpoint breaks."""
    log = commit_case(factory, screen())

    with factory() as session:
        rows = session.execute(select(LedgerLeaf).order_by(LedgerLeaf.leaf_index)).scalars().all()
    rebuilt = TransparencyLog(
        [LedgerEntry(row.case_id, row.verdict_digest, row.recorded_at) for row in rows]
    )

    assert rebuilt.root() == log.root()


def test_a_third_party_can_prove_the_case_was_logged(factory: sessionmaker[Session]) -> None:
    """Signed checkpoint, inclusion proof, no access to the system that made them."""
    key = Ed25519PrivateKey.generate()
    log = commit_case(factory, screen())
    checkpoint = log.checkpoint(key=key, signed_at=WHEN)

    assert verify_checkpoint(checkpoint, key=key.public_key())
    assert verify_inclusion(
        log.leaf(0), index=0, size=checkpoint.tree_size, proof=log.proof(0), root=checkpoint.root
    )


def test_the_report_for_a_stored_case_still_says_what_was_not_checked(
    factory: sessionmaker[Session],
) -> None:
    """A case reopened from storage is rendered under the same honesty rule."""
    commit_case(factory, screen())
    report = render_verdict(stored_verdict(factory))

    assert NOT_CHECKED_HEADING in report
    for notice in stored_verdict(factory).not_checked:
        assert " ".join(notice.split()) in " ".join(report.split())
