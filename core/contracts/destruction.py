"""What is left behind when retention destroys a case.

A retention policy that deletes a record and says nothing has replaced one
problem with another. The case is gone, which is what was required, but so is
any account of *why* it is gone — and an officer looking for it, or an auditor
years later, cannot tell a lawful destruction from a database that lost a row
or from somebody removing an inconvenient case.

So a destruction is itself a record, and it is appended to the transparency log
like any other. The log entry for the original decision stays where it is:
deleting a leaf breaks the Merkle chain for every entry after it, which is the
one thing the log cannot survive. See ADR 0003 and ADR 0006.

**This record deliberately does not say what the case decided.** No
``CLEARED``, no ``REJECTED``, no verdict. ADR 0006 already accepts that once
retention destroys a case, the log proves *that* a decision was made at a time
and has not been altered, but no longer what it said. Carrying the decision
forward here would quietly undo that: the outcome for a named traveller would
outlive the retention window that was supposed to end it, and the policy would
be cosmetic. What survives is the shape of the destruction, not its subject.

**Nor does it hold a document number**, in any form. It holds the opaque case
identifier, which the rest of the system already treats as safe to keep, and
which is in the ledger permanently regardless.
"""

from __future__ import annotations

import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.privacy.retention import ArtefactCategory


class DestructionRecord(BaseModel):
    """One lawful destruction of one stored case, and the policy that required it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    """Which case was destroyed. Opaque, and never a document number."""

    checkpoint_id: Annotated[str, Field(min_length=1, max_length=64)]
    """Which crossing point held the record. Stamped on every audit record."""

    category: ArtefactCategory
    """The retention category whose window expired."""

    window: datetime.timedelta
    """The window that was applied, so the arithmetic stays checkable later.

    Recorded rather than looked up, because a policy can be changed after the
    fact and an auditor needs to know which one was actually in force.
    """

    original_created_at: datetime.datetime
    """When the destroyed record was written. Must carry a timezone."""

    destroyed_at: datetime.datetime
    """When it was destroyed. Must carry a timezone."""

    reviews_destroyed: Annotated[int, Field(ge=0)]
    """How many officer reviews went with it.

    A count, never their content: a review carries a named officer and a note in
    their own words, both of which belong to the case and die with it.
    """

    @field_validator("original_created_at", "destroyed_at")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime.datetime) -> datetime.datetime:
        """Reject naive timestamps, which cannot be placed on a timeline."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = "must be timezone aware"
            raise ValueError(msg)
        return value

    @field_validator("window")
    @classmethod
    def _window_is_positive(cls, value: datetime.timedelta) -> datetime.timedelta:
        """Reject a window of zero or less, which no policy can have required."""
        if value <= datetime.timedelta(0):
            msg = "the retention window must be positive"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _destroyed_after_it_was_created(self) -> DestructionRecord:
        """Reject a destruction that precedes the record it destroyed."""
        if self.destroyed_at < self.original_created_at:
            msg = "a record cannot be destroyed before it was created"
            raise ValueError(msg)
        return self

    @property
    def due_at(self) -> datetime.datetime:
        """When destruction fell due, by the policy recorded here.

        Returns:
            The deadline. Computed from the stored window rather than from the
            current policy, so a later change to the policy cannot make a past
            destruction look early or late.
        """
        return self.original_created_at + self.window

    @property
    def was_overdue(self) -> bool:
        """Whether destruction happened after it fell due.

        Returns:
            Whether the record outlived its window. A sweep that runs daily
            will show this as true almost always, by less than a day; it is
            worth surfacing because a large gap means the sweep stopped running.
        """
        return self.destroyed_at > self.due_at
