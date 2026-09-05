"""The outcome of one screening case, and the record that has to survive audit.

A :class:`Verdict` is what the trust ladder returns. It holds the decision, the
reasoning in plain language, the findings behind it, the advisory context that
did *not* drive it, and — required by the honesty rule in CLAUDE.md — an
explicit list of what was **not** checked.

The class carries one structural guard of its own: a ``CLEARED`` verdict is
rejected unless the evidence contains an affirmative result from Rung 0 or
Rung 1. Policy in :mod:`core.trust.ladder` is stricter than that, but this
floor holds regardless of which policy is in force, so no future change to the
ladder can produce a clearance resting on inference alone.
"""

from __future__ import annotations

import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.contracts.enums import Decision, Result, Rung
from core.contracts.evidence import Evidence
from core.contracts.finding import Finding
from core.contracts.provenance import Provenance

CLEARING_BASIS: frozenset[tuple[Rung, Result]] = frozenset(
    {
        (Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
        (Rung.DETERMINISTIC, Result.PASS),
    }
)
"""The only (rung, result) pairs that can support a clearance. Inference is absent by design."""


class Verdict(BaseModel):
    """The complete, immutable record of one screening decision.

    Everything an officer was shown, everything the system relied on, and
    everything it could not check, in one object that serialises to the audit
    ledger unchanged.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Decision
    """What happens to the traveller's document. One of exactly three values."""

    basis: Annotated[tuple[str, ...], Field(min_length=1)]
    """Why this decision, in plain sentences. Always populated, including for clearances."""

    findings: tuple[Finding, ...] = ()
    """Everything that bore on the decision, positive and negative."""

    advisories: tuple[Finding, ...] = ()
    """Rung 3 context. Held separately so it can never be read as a reason for the decision."""

    not_checked: tuple[str, ...] = ()
    """What this screening did not establish. Silence about a missing check is a defect."""

    evidence: tuple[Evidence, ...] = ()
    """The full unedited detector output the decision was computed from."""

    provenance: Provenance | None = None
    """What was screened, when it was captured, and by which checkpoint."""

    decided_at: datetime.datetime
    """When the ladder resolved this case. Must carry a timezone."""

    policy_version: Annotated[str, Field(min_length=1, max_length=64)]
    """Which resolution policy produced this decision, so old cases stay interpretable."""

    @field_validator("decided_at")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime.datetime) -> datetime.datetime:
        """Reject naive timestamps, which are unusable in an audit record."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = "decided_at must be timezone aware"
            raise ValueError(msg)
        return value

    @field_validator("basis")
    @classmethod
    def _basis_has_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject a blank justification; every decision must say why in words."""
        for sentence in value:
            if not sentence.strip():
                msg = "every basis sentence must contain text"
                raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _clearance_rests_on_an_authoritative_check(self) -> Verdict:
        """Reject a clearance that no Rung 0 or Rung 1 affirmative result supports.

        This is the structural half of rule 1 in CLAUDE.md. Inference and
        context cannot clear a document no matter how confident they are,
        because no combination of Rung 2 or Rung 3 evidence can put a
        qualifying pair into the evidence list.
        """
        if self.decision is not Decision.CLEARED:
            return self
        if not any((item.rung, item.result) in CLEARING_BASIS for item in self.evidence):
            msg = "CLEARED requires an affirmative Rung 0 or Rung 1 result in the evidence"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _advisories_are_contextual(self) -> Verdict:
        """Reject decision-bearing findings filed as advisories, or the reverse."""
        for advisory in self.advisories:
            if advisory.rung is not Rung.CONTEXTUAL:
                msg = "advisories may only hold Rung 3 findings"
                raise ValueError(msg)
        for finding in self.findings:
            if finding.rung is Rung.CONTEXTUAL:
                msg = "Rung 3 findings belong in advisories, not findings"
                raise ValueError(msg)
        return self
