"""One line of the report an officer actually reads.

A :class:`Finding` is derived from :class:`~core.contracts.evidence.Evidence`
by the trust ladder. Evidence is written for the record; a finding is written
for a person standing at a barrier with a queue behind them. It keeps the link
back to the detector and the standard so that the short sentence on screen can
always be expanded into the full justification.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.contracts.enums import Rung, Severity


class Finding(BaseModel):
    """A single officer-facing statement about the document, with its provenance.

    Immutable. Findings never carry a score: a number on screen invites an
    officer to weigh it against another number, which is exactly the reasoning
    the trust ladder exists to prevent. If a Rung 2 detector raised a concern,
    the finding says so in words and the underlying score stays in the evidence
    record for the audit trail.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: Annotated[str, Field(min_length=1, max_length=64)]
    """Stable machine-readable label for this class of finding, for use in filters and stats."""

    severity: Severity
    """How prominently the console should present this."""

    headline: Annotated[str, Field(min_length=1, max_length=200)]
    """One sentence, plain language, no jargon. What an officer sees first."""

    detail: tuple[str, ...] = ()
    """The detector's own reasons, carried through verbatim."""

    detector_id: Annotated[str, Field(min_length=1, max_length=128)]
    """Which detector produced the evidence behind this finding."""

    rung: Rung
    """The rung of the evidence behind this finding, so weight is never guessed."""

    standard_ref: Annotated[str | None, Field(max_length=256)] = None
    """The clause that makes this finding defensible, when one applies."""

    artifacts: tuple[str, ...] = ()
    """Exhibits the officer can open: heatmaps, crops, decoded payloads."""

    @field_validator("headline")
    @classmethod
    def _headline_has_text(cls, value: str) -> str:
        """Reject a headline that is only whitespace."""
        if not value.strip():
            msg = "headline must contain text"
            raise ValueError(msg)
        return value
