"""An officer's decision, and the things it refuses to be.

The contract exists to keep two records apart: what the automated checks
established, and what a person decided about it. Most of this file is about the
refusals, because a review that could be blank, unattributed, or recorded as
"still needs review" would let a queue be emptied without anything being
decided.
"""

from __future__ import annotations

import datetime

import pytest
from pydantic import ValidationError

from core.contracts import Decision, OfficerReview
from core.contracts.review import REVIEW_OUTCOMES

WHEN = datetime.datetime(2026, 9, 7, 9, 30, tzinfo=datetime.UTC)


def review(**overrides: object) -> OfficerReview:
    """Build a valid review, so a test can break exactly one thing."""
    fields: dict[str, object] = {
        "case_id": "2026-09-07-A3F91C4D2B",
        "outcome": Decision.CLEARED,
        "officer_id": "officer-12",
        "note": "Bearer produced a second document and the photograph matches.",
        "system_decision": Decision.MANUAL_REVIEW,
        "recorded_at": WHEN,
    }
    fields.update(overrides)
    return OfficerReview(**fields)


def test_a_review_records_who_decided_and_why() -> None:
    """The ordinary case, so the refusals below are refusals of something real."""
    recorded = review()

    assert recorded.officer_id == "officer-12"
    assert recorded.outcome is Decision.CLEARED


def test_a_review_cannot_conclude_manual_review() -> None:
    """`MANUAL_REVIEW` is the state the case is in, not a decision about it."""
    with pytest.raises(ValidationError, match="CLEARED or REJECTED"):
        review(outcome=Decision.MANUAL_REVIEW)


def test_the_available_outcomes_are_exactly_two() -> None:
    """Pinned, so a third decision cannot be added without this test noticing."""
    assert frozenset({Decision.CLEARED, Decision.REJECTED}) == REVIEW_OUTCOMES


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_a_review_without_a_reason_is_refused(blank: str) -> None:
    """A note is required, including for a rejection. Especially for a rejection."""
    with pytest.raises(ValidationError):
        review(note=blank)


@pytest.mark.parametrize("blank", ["", "   "])
def test_an_unattributed_review_is_refused(blank: str) -> None:
    """An override nobody signed is not a review, it is a change to the record."""
    with pytest.raises(ValidationError):
        review(officer_id=blank)


def test_a_naive_timestamp_is_refused() -> None:
    """An audit record dated without a timezone cannot be placed in time."""
    with pytest.raises(ValidationError, match="timezone"):
        review(recorded_at=datetime.datetime(2026, 9, 7, 9, 30))  # Naive on purpose.


def test_an_unknown_field_is_refused() -> None:
    """`extra="forbid"`: a typo must not become a field nothing reads."""
    with pytest.raises(ValidationError):
        OfficerReview(
            case_id="c1",
            outcome=Decision.CLEARED,
            officer_id="officer-12",
            note="Looked at it.",
            system_decision=Decision.MANUAL_REVIEW,
            recorded_at=WHEN,
            supervisor="someone",
        )


def test_a_review_is_frozen() -> None:
    """A decision that could be edited after the fact is not a record of anything."""
    with pytest.raises(ValidationError):
        review().officer_id = "someone-else"


def test_clearing_a_case_the_system_would_not_is_an_override() -> None:
    """The ordinary manual review: a person clears what the checks could not."""
    assert review(outcome=Decision.CLEARED, system_decision=Decision.MANUAL_REVIEW)
    assert review().overrides_the_system


def test_agreeing_with_the_system_is_not_an_override() -> None:
    """An officer confirming a rejection is a decision, not a contradiction."""
    recorded = review(outcome=Decision.REJECTED, system_decision=Decision.REJECTED)

    assert not recorded.overrides_the_system


def test_rejecting_a_document_the_system_cleared_is_an_override() -> None:
    """The direction that should draw a second look, and the console marks it."""
    recorded = review(outcome=Decision.REJECTED, system_decision=Decision.CLEARED)

    assert recorded.overrides_the_system
