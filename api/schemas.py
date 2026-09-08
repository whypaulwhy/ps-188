"""What crosses the HTTP boundary, kept separate from the core contracts.

The core contracts are the record. These are the wire format, and they are
separate on purpose: a field renamed for a client should not be able to change
what is stored in an audit record, and a contract field added later should not
silently start appearing in responses.

Two things every screening response carries, because CLAUDE.md requires them of
every report and a JSON body is a report:

* ``not_checked`` — what this screening did not establish, never omitted and
  never empty-by-default;
* ``report`` — the rendered officer text, so a client that shows a person
  something is showing them the same words the console does, rather than
  inventing its own phrasing for a decision.

No score appears anywhere in this module. A Rung 2 score is in the stored
evidence for the audit trail; putting it on the wire invites a client to build
a dashboard that ranks travellers by it.
"""

from __future__ import annotations

import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from core.contracts import Decision, Finding, Verdict
from db.recording import CaseView


class FindingOut(BaseModel):
    """One officer-facing statement about the document."""

    model_config = ConfigDict(frozen=True)

    code: str
    severity: str
    headline: str
    detail: tuple[str, ...]
    detector_id: str
    rung: int
    rung_name: str
    standard_ref: str | None

    @classmethod
    def of(cls, finding: Finding) -> FindingOut:
        """Convert a finding for the wire."""
        return cls(
            code=finding.code,
            severity=finding.severity.name,
            headline=finding.headline,
            detail=finding.detail,
            detector_id=finding.detector_id,
            rung=int(finding.rung),
            rung_name=finding.rung.name,
            standard_ref=finding.standard_ref,
        )


class ReviewOut(BaseModel):
    """One officer decision on a case."""

    model_config = ConfigDict(frozen=True)

    outcome: Decision
    officer_id: str
    note: str
    system_decision: Decision
    overrides_the_system: bool
    recorded_at: datetime.datetime


class ScreeningOut(BaseModel):
    """The result of one screening, and everything it did not establish."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    checkpoint_id: str
    decision: Decision
    standing_decision: Decision
    awaiting_review: bool
    basis: tuple[str, ...]
    findings: tuple[FindingOut, ...]
    advisories: tuple[FindingOut, ...]
    not_checked: tuple[str, ...]
    not_extracted: tuple[str, ...] = ()
    reviews: tuple[ReviewOut, ...] = ()
    leaf_index: int
    decided_at: datetime.datetime
    policy_version: str
    report: str


class ReviewIn(BaseModel):
    """An officer's decision, as submitted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    officer_id: Annotated[str, Field(min_length=1, max_length=64)]
    outcome: Decision
    note: Annotated[str, Field(min_length=1, max_length=2000)]


class CheckpointOut(BaseModel):
    """A signed statement about the log, for publication outside this system."""

    model_config = ConfigDict(frozen=True)

    tree_size: int
    root: str
    signed_at: datetime.datetime
    signature: str
    public_key: str


class ProofOut(BaseModel):
    """An inclusion proof, verifiable without any part of this system."""

    model_config = ConfigDict(frozen=True)

    leaf_index: int
    leaf: str
    tree_size: int
    proof: tuple[str, ...]
    root: str


class ConsistencyOut(BaseModel):
    """A proof that the log extends an earlier published checkpoint, unchanged."""

    model_config = ConfigDict(frozen=True)

    old_size: int
    new_size: int
    proof: tuple[str, ...]
    root: str


class HealthOut(BaseModel):
    """What this deployment can do, and what it cannot."""

    model_config = ConfigDict(frozen=True)

    checkpoint_id: str
    detectors: tuple[str, ...]
    unavailable: tuple[str, ...]
    cases_recorded: int
    ledger_entries: int


def screening_out(
    view: CaseView, *, report: str, not_extracted: tuple[str, ...] = ()
) -> ScreeningOut:
    """Build the wire form of a case.

    Args:
        view: The stored case, with any reviews.
        report: The rendered officer text for its verdict.
        not_extracted: What extraction could not read, when this is the response
            to a fresh screening. Absent when reading a case back, because it is
            a property of the capture rather than of the record.

    Returns:
        The response body.
    """
    verdict: Verdict = view.verdict
    return ScreeningOut(
        case_id=view.case_id,
        checkpoint_id=view.checkpoint_id,
        decision=verdict.decision,
        standing_decision=view.standing_decision,
        awaiting_review=view.awaiting_review,
        basis=verdict.basis,
        findings=tuple(FindingOut.of(finding) for finding in verdict.findings),
        advisories=tuple(FindingOut.of(finding) for finding in verdict.advisories),
        not_checked=verdict.not_checked,
        not_extracted=not_extracted,
        reviews=tuple(
            ReviewOut(
                outcome=review.outcome,
                officer_id=review.officer_id,
                note=review.note,
                system_decision=review.system_decision,
                overrides_the_system=review.overrides_the_system,
                recorded_at=review.recorded_at,
            )
            for review in view.reviews
        ),
        leaf_index=view.leaf_index,
        decided_at=verdict.decided_at,
        policy_version=verdict.policy_version,
        report=report,
    )
