"""What a destruction record must refuse, and what it must never carry.

`core/` requires 100% branch coverage, so every validator here is driven both
ways. Two of these tests are about the contract's *shape* rather than its
validation, and they are the ones worth keeping if the rest are ever trimmed:
a destruction record must not be able to carry the decision it destroyed, and
it must not be able to carry a document number.
"""

from __future__ import annotations

import datetime
from typing import Final

import pytest
from pydantic import ValidationError

from core.contracts import DestructionRecord
from core.privacy.retention import ArtefactCategory

CREATED_AT: Final[datetime.datetime] = datetime.datetime(2026, 1, 1, 9, 0, tzinfo=datetime.UTC)
"""When the destroyed record was written."""

WINDOW: Final[datetime.timedelta] = datetime.timedelta(days=30)
"""An ordinary case-record retention window."""


def destruction(**overrides: object) -> DestructionRecord:
    """Build a valid destruction record, overriding one field at a time."""
    fields: dict[str, object] = {
        "case_id": "case-0001",
        "checkpoint_id": "ssb-demo-01",
        "category": ArtefactCategory.CASE_RECORD,
        "window": WINDOW,
        "original_created_at": CREATED_AT,
        "destroyed_at": CREATED_AT + WINDOW,
        "reviews_destroyed": 0,
    }
    fields.update(overrides)
    return DestructionRecord(**fields)  # type: ignore[arg-type]


# The ordinary path


def test_a_destruction_record_is_frozen() -> None:
    """An audit record that can be edited after the fact records nothing."""
    record = destruction()

    with pytest.raises(ValidationError):
        record.case_id = "case-0002"  # type: ignore[misc]


def test_it_reports_when_destruction_fell_due() -> None:
    """The deadline is computed from the window stored on the record itself."""
    assert destruction().due_at == CREATED_AT + WINDOW


def test_a_destruction_on_the_deadline_is_not_overdue() -> None:
    """The boundary belongs to the window, not to the overdue side of it."""
    assert destruction(destroyed_at=CREATED_AT + WINDOW).was_overdue is False


def test_a_late_destruction_is_reported_as_overdue() -> None:
    """A large gap means the sweep stopped running, which an operator must see."""
    late = destruction(destroyed_at=CREATED_AT + WINDOW + datetime.timedelta(days=9))

    assert late.was_overdue is True


# What it refuses


def test_a_naive_created_timestamp_is_refused() -> None:
    """An instant without a timezone cannot be placed on a timeline."""
    with pytest.raises(ValidationError, match="timezone aware"):
        destruction(original_created_at=CREATED_AT.replace(tzinfo=None))


def test_a_naive_destroyed_timestamp_is_refused() -> None:
    """Same rule, applied to the other end of the record."""
    with pytest.raises(ValidationError, match="timezone aware"):
        destruction(destroyed_at=(CREATED_AT + WINDOW).replace(tzinfo=None))


def test_a_zero_window_is_refused() -> None:
    """No policy can have required a window of nothing."""
    with pytest.raises(ValidationError, match="must be positive"):
        destruction(window=datetime.timedelta(0))


def test_a_negative_window_is_refused() -> None:
    """The other side of the same boundary."""
    with pytest.raises(ValidationError, match="must be positive"):
        destruction(window=datetime.timedelta(days=-1))


def test_destruction_before_creation_is_refused() -> None:
    """A record cannot be destroyed before it existed."""
    with pytest.raises(ValidationError, match="cannot be destroyed before"):
        destruction(destroyed_at=CREATED_AT - datetime.timedelta(seconds=1))


def test_destruction_at_the_moment_of_creation_is_allowed() -> None:
    """The boundary itself is valid: a zero-length life is odd but not impossible."""
    assert destruction(destroyed_at=CREATED_AT).was_overdue is False


def test_a_negative_review_count_is_refused() -> None:
    """A count of destroyed reviews below zero is not a count."""
    with pytest.raises(ValidationError):
        destruction(reviews_destroyed=-1)


def test_an_empty_case_id_is_refused() -> None:
    """A tombstone that does not say which case it is about says nothing."""
    with pytest.raises(ValidationError):
        destruction(case_id="")


def test_an_empty_checkpoint_id_is_refused() -> None:
    """Every audit record is stamped with the crossing that made it."""
    with pytest.raises(ValidationError):
        destruction(checkpoint_id="")


# The two that matter most


def test_a_destruction_record_cannot_carry_the_decision() -> None:
    """The outcome must not outlive the window that was meant to end it.

    ADR 0006 accepts that a destroyed case leaves a log proving a decision was
    made but not what it said. A `decision` field here would quietly reverse
    that, and the retention policy would become cosmetic.
    """
    with pytest.raises(ValidationError, match="decision"):
        destruction(decision="CLEARED")


def test_a_destruction_record_cannot_carry_a_verdict() -> None:
    """Nor the verdict itself, by the same argument."""
    with pytest.raises(ValidationError, match="verdict"):
        destruction(verdict_json='{"decision":"CLEARED"}')


def test_the_recorded_window_is_used_rather_than_the_current_policy() -> None:
    """A policy shortened later must not make a past destruction look late.

    The record carries the window that was in force, so the arithmetic an
    auditor checks is the arithmetic that was actually applied.
    """
    generous = destruction(window=datetime.timedelta(days=365))

    assert generous.due_at == CREATED_AT + datetime.timedelta(days=365)
    assert generous.was_overdue is False
