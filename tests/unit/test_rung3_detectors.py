"""Rung 3 advisories, and the guarantee that they cannot decide anything.

The last section is the exit criterion for this phase. Everything else is
supporting: what these detectors say, and that they say it about documents
rather than about people.
"""

from __future__ import annotations

import datetime

import pytest

from core.contracts import Decision, Evidence, Result, Rung, TextZone, ZoneName
from core.privacy import DeploymentKey, IdentifierKind, RawIdentifier, hash_document_number
from core.standards.mrz.parse import render_td3
from core.trust import resolve
from detectors.rung3_context import repeat_identity, watchlist
from detectors.rung3_context.context_store import (
    Crossing,
    CrossingHistory,
    Watchlist,
    WatchlistEntry,
)
from tests.support import DECIDED_AT, evidence, provenance, subject

KEY = DeploymentKey.generate()
NUMBER = "Z0000001"
EARLIER = DECIDED_AT - datetime.timedelta(days=30)


def digest_of(number: str = NUMBER) -> str:
    """Return the digest a detector will compute for a document number."""
    return hash_document_number(RawIdentifier(number, kind=IdentifierKind.PASSPORT), key=KEY)


def with_strip(number: str = NUMBER, *, complete: bool = True):  # noqa: ANN201
    """Build a subject carrying a readable strip for a given document number."""
    lines = render_td3(
        document_code="P<",
        issuing_state="UTO",
        surname="SPECIMEN",
        given_names=("TEST",),
        document_number=number,
        nationality="UTO",
        date_of_birth="900101",
        sex="M",
        date_of_expiry="350101",
    )
    return subject(
        zones=(TextZone(name=ZoneName.MRZ, lines=lines, complete=complete),),
        provenance=provenance(captured_at=DECIDED_AT, received_at=DECIDED_AT),
    )


def history(*crossings: Crossing) -> CrossingHistory:
    """Build a crossing history."""
    return CrossingHistory(crossings)


def run_repeat(subject_under_test, store: CrossingHistory) -> Evidence:  # noqa: ANN001
    """Run the repeat identity detector and return its single piece of evidence."""
    (item,) = repeat_identity.build(store, key=KEY).run(subject_under_test)
    return item


def run_watchlist(subject_under_test, listed: Watchlist) -> Evidence:  # noqa: ANN001
    """Run the watchlist detector and return its single piece of evidence."""
    (item,) = watchlist.build(listed, key=KEY).run(subject_under_test)
    return item


# ---------------------------------------------------------------------------
# Repeat identity
# ---------------------------------------------------------------------------


def test_a_first_crossing_raises_no_flag() -> None:
    """A document nobody has seen is not remarkable."""
    item = run_repeat(with_strip(), history(Crossing(digest_of("OTHER123"), EARLIER, "post-a")))

    assert item.result is Result.NO_FLAG


def test_a_repeat_crossing_is_flagged_without_alarm() -> None:
    """Frequent crossing is ordinary here, and the wording has to say so."""
    item = run_repeat(
        with_strip(),
        history(
            Crossing(digest_of(), EARLIER, "post-a"),
            Crossing(digest_of(), EARLIER + datetime.timedelta(days=1), "post-b"),
        ),
    )

    assert item.result is Result.FLAG_RAISED
    assert "2 time(s) before" in item.reasons[0]
    assert "not by itself a reason for concern" in item.reasons[1]


def test_a_case_is_not_its_own_history() -> None:
    """A sighting at or after the current capture must not count as a previous one."""
    item = run_repeat(with_strip(), history(Crossing(digest_of(), DECIDED_AT, "post-a")))

    assert item.result is Result.NO_FLAG


def test_a_different_document_is_a_different_history() -> None:
    """The deliberate boundary: this links documents, not people."""
    item = run_repeat(with_strip("Z9999999"), history(Crossing(digest_of(), EARLIER, "post-a")))

    assert item.result is Result.NO_FLAG


def test_an_empty_history_is_reported_as_unchecked() -> None:
    """Not consulted is a different statement from consulted and clean."""
    item = run_repeat(with_strip(), history())

    assert item.result is Result.NOT_CHECKED


def test_an_unreadable_document_is_reported_as_unchecked() -> None:
    """With no number there is nothing to look up, and silence would mislead."""
    item = run_repeat(with_strip(complete=False), history(Crossing(digest_of(), EARLIER, "post-a")))

    assert item.result is Result.NOT_CHECKED
    assert "could not be identified" in item.reasons[0]


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------


def test_a_listed_document_is_flagged_with_the_operator_reason() -> None:
    """The officer sees why it is listed, in the operator's own words."""
    listed = Watchlist.from_numbers([(NUMBER, "Reported lost by its holder.")], key=KEY)

    item = run_watchlist(with_strip(), listed)

    assert item.result is Result.FLAG_RAISED
    assert item.reasons[1] == "Reported lost by its holder."


def test_an_unlisted_document_raises_no_flag() -> None:
    """The ordinary case."""
    listed = Watchlist.from_numbers([("Z5555555", "Some reason.")], key=KEY)

    assert run_watchlist(with_strip(), listed).result is Result.NO_FLAG


def test_no_watchlist_is_reported_as_unchecked() -> None:
    """A checkpoint given no list must not report that a traveller is not on one."""
    item = run_watchlist(with_strip(), Watchlist())

    assert item.result is Result.NOT_CHECKED
    assert "holds no watchlist" in item.reasons[0]


def test_the_watchlist_holds_no_document_numbers() -> None:
    """Rule 3 applies to an operator's list as much as to a case record."""
    listed = Watchlist.from_numbers([(NUMBER, "Some reason.")], key=KEY)

    for entry in listed:
        assert NUMBER not in entry.digest
        assert len(entry.digest) == 64


def test_two_entries_cannot_share_a_digest() -> None:
    """A duplicate would make the reason shown to an officer arbitrary."""
    with pytest.raises(ValueError, match="cannot share a digest"):
        Watchlist([WatchlistEntry(digest_of(), "One reason."), WatchlistEntry(digest_of(), "Two.")])


def test_a_crossing_cannot_be_keyed_on_a_document_number() -> None:
    """The structural guard: a history holds digests, not numbers."""
    with pytest.raises(ValueError, match="never on a document number"):
        Crossing(NUMBER, EARLIER, "post-a")


def test_a_crossing_needs_a_timezone() -> None:
    """A sighting that cannot be placed on a timeline cannot be ordered."""
    with pytest.raises(ValueError, match="timezone aware"):
        Crossing(digest_of(), datetime.datetime(2026, 1, 1, 12, 0), "post-a")


# ---------------------------------------------------------------------------
# The exit criterion: Rung 3 decides nothing
# ---------------------------------------------------------------------------


def flagged_context() -> tuple[Evidence, ...]:
    """Return the loudest pair of advisories these detectors can produce."""
    listed = Watchlist.from_numbers([(NUMBER, "Wanted in connection with a matter.")], key=KEY)
    document = with_strip()
    return (
        run_repeat(document, history(Crossing(digest_of(), EARLIER, "post-a"))),
        run_watchlist(document, listed),
    )


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ((), Decision.MANUAL_REVIEW),
        (((Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),), Decision.CLEARED),
        (((Rung.DETERMINISTIC, Result.FAIL),), Decision.REJECTED),
        (((Rung.DETERMINISTIC, Result.PASS),), Decision.MANUAL_REVIEW),
        (((Rung.INFERENCE, Result.SUSPICIOUS),), Decision.MANUAL_REVIEW),
    ],
)
def test_real_advisories_never_change_a_decision(
    base: tuple[tuple[Rung, Result], ...], expected: Decision
) -> None:
    """The exit criterion for this phase, run through the real detectors.

    The ladder already guarantees this structurally. What this adds is the two
    detectors that would break the guarantee if it were not enforced: a
    watchlist hit and a repeat crossing, both raised, against every decision the
    system can reach. Nothing moves.

    Note the second row in particular. A document with a valid issuer signature
    and a watchlist hit still clears, because a watchlist is not evidence about
    the document. Whether that is the right operational policy is a question for
    the officer, and Rung 3 exists so that they are the one answering it.
    """
    prior = [evidence(*pair) for pair in base]

    without = resolve(prior, decided_at=DECIDED_AT)
    with_context = resolve([*prior, *flagged_context()], decided_at=DECIDED_AT)

    assert without.decision is expected
    assert with_context.decision is expected


def test_advisories_reach_the_officer_without_touching_the_decision() -> None:
    """Filed separately from the findings, so they cannot be read as reasons."""
    verdict = resolve(
        [evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID), *flagged_context()],
        decided_at=DECIDED_AT,
    )

    assert verdict.decision is Decision.CLEARED
    assert len(verdict.advisories) == 2
    assert all(advisory.rung is Rung.CONTEXTUAL for advisory in verdict.advisories)
    assert all(finding.rung is not Rung.CONTEXTUAL for finding in verdict.findings)


def test_an_unconsulted_watchlist_reaches_the_officer_as_a_missing_check() -> None:
    """The reason Rung 3 needed a third result at all."""
    verdict = resolve(
        [run_watchlist(with_strip(), Watchlist())],
        decided_at=DECIDED_AT,
    )

    assert verdict.advisories == ()
    assert any("holds no watchlist" in line for line in verdict.not_checked)
