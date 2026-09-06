"""What an officer decided, kept separate from what the system decided.

A case the ladder sends to ``MANUAL_REVIEW`` is a case a person has to resolve,
and that resolution is a record in its own right. It is **not** an edit to the
verdict. Three reasons, in order of importance:

1. **The verdict must stay true.** It says what the automated checks
   established. If an officer clearing a document rewrote it to ``CLEARED``, the
   record would claim the system verified something it did not, and rule 1 of
   CLAUDE.md would be violated by the storage layer rather than by the ladder.
2. **The audit trail is append-only.** A review is a new entry in the
   transparency log, digested like a verdict. Editing a stored decision is the
   thing the log exists to detect; the system must not be the first to do it.
3. **A case can be reviewed more than once.** A supervisor revisiting an
   officer's call is a sequence of records, not a value being overwritten.

**An officer may clear a document the system would not, and may reject one it
found nothing wrong with.** That is what manual review is for, and refusing it
would not prevent the override — it would move it onto paper, where nothing is
recorded. What this contract insists on is that the override be attributable
and explained: a named officer and a note, both required, neither blank.

``MANUAL_REVIEW`` is not an available outcome. It is the state the case is
already in, and recording it as a decision would let a queue be emptied without
anything being decided.
"""

from __future__ import annotations

import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.contracts.enums import Decision

REVIEW_OUTCOMES: frozenset[Decision] = frozenset({Decision.CLEARED, Decision.REJECTED})
"""What an officer may conclude. Deliberately excludes ``MANUAL_REVIEW``."""


class OfficerReview(BaseModel):
    """One human decision on one case, attributable and explained."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    """Which case was reviewed. Opaque, and never a document number."""

    outcome: Decision
    """What the officer decided. Must be ``CLEARED`` or ``REJECTED``."""

    officer_id: Annotated[str, Field(min_length=1, max_length=64)]
    """Who decided. An unattributed override is not a review."""

    note: Annotated[str, Field(min_length=1, max_length=2000)]
    """Why, in the officer's own words. Required, including for a rejection."""

    system_decision: Decision
    """What the system had decided, so an override is visible as one."""

    recorded_at: datetime.datetime
    """When the officer decided. Must carry a timezone."""

    @field_validator("outcome")
    @classmethod
    def _outcome_is_a_decision(cls, value: Decision) -> Decision:
        """Reject ``MANUAL_REVIEW``, which resolves nothing."""
        if value not in REVIEW_OUTCOMES:
            msg = "an officer review must conclude CLEARED or REJECTED"
            raise ValueError(msg)
        return value

    @field_validator("note", "officer_id")
    @classmethod
    def _has_text(cls, value: str) -> str:
        """Reject whitespace standing in for an answer."""
        if not value.strip():
            msg = "must contain text"
            raise ValueError(msg)
        return value

    @field_validator("recorded_at")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime.datetime) -> datetime.datetime:
        """Reject naive timestamps, which are unusable in an audit record."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = "recorded_at must be timezone aware"
            raise ValueError(msg)
        return value

    @property
    def overrides_the_system(self) -> bool:
        """Whether the officer reached a different conclusion from the system.

        Returns:
            Whether the outcome differs from what the system decided. The
            console shows these differently: an officer clearing a document the
            checks could not clear is the ordinary case, and one rejecting a
            document nothing was found wrong with is worth a second look.
        """
        return self.outcome is not self.system_decision
