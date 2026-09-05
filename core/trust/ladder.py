"""Resolution of detector evidence into a single screening decision.

This is the file the whole system turns on. Everything else gathers material;
this decides what happens to a person standing at a barrier. It is a pure
function over data: no file system, no network, no database, no model.

The rules, in the order they are applied:

1. **Rejection wins.** Any Rung 0 ``PROOF_INVALID`` or any Rung 1 ``FAIL`` ends
   the case as ``REJECTED``, even if some other detector proved a signature
   valid. A document that both carries a genuine signature and violates a fixed
   standard is a document with something wrong with it.
2. **Concern escalates.** A Rung 2 ``SUSPICIOUS`` forces ``MANUAL_REVIEW``.
3. **Proof clears.** A Rung 0 ``PROOF_VALID`` with nothing above it clears.
4. **Everything else is unresolved**, and unresolved means ``MANUAL_REVIEW``.

Rung 3 appears nowhere in that list. Contextual signals are attached to the
verdict as advisories and never touch the decision.

Two consequences are worth stating explicitly, because they are the properties
this system is judged on:

* **No clearance without authority.** ``CLEARED`` is reachable only through
  step 3, which requires cryptographic proof. A Rung 2 detector reporting
  maximum confidence in authenticity — a suspicion score of ``0.0`` — moves
  nothing, because rule 3 never consults it. The evidence contract makes this
  structural rather than merely intended: a Rung 2 detector cannot even express
  ``PROOF_VALID``, and :class:`~core.contracts.verdict.Verdict` refuses to
  construct a clearance without a qualifying Rung 0 or Rung 1 result.
* **Monotonicity.** Adding Rung 2 or Rung 3 evidence to any case can only leave
  the decision unchanged or make it more severe. It can never soften one.

.. note::
   Step 2 runs before step 3, which is stricter than the resolution order in
   CLAUDE.md, where ``PROOF_VALID`` short-circuits immediately. The reason is
   rule 1 of that same document, which states that uncertainty routes to
   ``MANUAL_REVIEW`` and overrides anything that conflicts with it. A valid
   issuer signature proves the *document* is genuine; it says nothing about
   whether the person presenting it is its holder, which is exactly what a
   Rung 2 face check reports on. Escalating there is not a lower rung
   overriding a higher one — the signature is still recorded as valid, and no
   Rung 2 detector can cause a ``REJECTED``. It is the system declining to
   clear a case a human has not looked at. See ``docs/trust-ladder.md``.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterable, Sequence

from core.contracts import Decision, Evidence, Finding, Provenance, Result, Rung, Verdict
from core.trust import policy

_REJECTION_HEADER: str = (
    "This document was rejected because a check that cannot be argued with failed."
)
_ESCALATION_HEADER: str = (
    "This document was sent for manual review because an automated check raised a concern."
)
_CLEARANCE_HEADER: str = (
    "This document was cleared because the issuing authority's digital signature was verified."
)
_UNPROVEN_HEADER: str = (
    "This document was sent for manual review because nothing available established that it is "
    "genuine."
)
_NOTHING_RAN_HEADER: str = (
    "This document was sent for manual review because no checks were run on it at all."
)
_NOTHING_RAN_NOTICE: str = "Nothing about this document was checked."


def resolve(
    evidence: Sequence[Evidence],
    *,
    provenance: Provenance | None = None,
    decided_at: datetime.datetime | None = None,
) -> Verdict:
    """Resolve a case's evidence into one verdict.

    Args:
        evidence: Everything every detector reported about this case, in any
            order. An empty sequence is valid and resolves to
            ``MANUAL_REVIEW``: a screening that checked nothing has established
            nothing.
        provenance: What was screened, carried onto the verdict for the audit
            record. Optional so that the ladder can be reasoned about and
            tested without a capture.
        decided_at: The instant to stamp on the verdict. Pass it to keep this
            call a pure function of its arguments; omit it and the current UTC
            time is read, which is the only impurity in this module.

    Returns:
        A :class:`~core.contracts.verdict.Verdict` holding the decision, the
        plain-language basis for it, the findings behind it, the Rung 3
        advisories that did not bear on it, and an explicit account of what was
        not checked.
    """
    items = tuple(evidence)

    rejecting = _matching(items, policy.REJECTING)
    escalating = _matching(items, policy.ESCALATING)
    proving = _matching(items, policy.PROVING)

    if rejecting:
        decision = Decision.REJECTED
        basis = _basis(_REJECTION_HEADER, rejecting)
    elif escalating:
        decision = Decision.MANUAL_REVIEW
        basis = _basis(_ESCALATION_HEADER, escalating)
    elif proving:
        decision = Decision.CLEARED
        basis = _basis(_CLEARANCE_HEADER, proving)
    elif items:
        decision = Decision.MANUAL_REVIEW
        basis = (_UNPROVEN_HEADER,)
    else:
        decision = Decision.MANUAL_REVIEW
        basis = (_NOTHING_RAN_HEADER,)

    return Verdict(
        decision=decision,
        basis=basis,
        findings=_findings(items),
        advisories=_advisories(items),
        not_checked=_not_checked(items),
        evidence=items,
        provenance=provenance,
        decided_at=decided_at if decided_at is not None else datetime.datetime.now(datetime.UTC),
        policy_version=policy.POLICY_VERSION,
    )


def _matching(
    items: Sequence[Evidence], selector: frozenset[tuple[Rung, Result]]
) -> tuple[Evidence, ...]:
    """Return the evidence whose rung and result appear in a policy table."""
    return tuple(item for item in items if (item.rung, item.result) in selector)


def _basis(header: str, drivers: Iterable[Evidence]) -> tuple[str, ...]:
    """Build the plain-language justification: one header, then the driving reasons."""
    sentences = [header]
    for driver in drivers:
        sentences.extend(driver.reasons)
    return tuple(sentences)


def _to_finding(item: Evidence) -> Finding:
    """Convert one piece of evidence into its officer-facing finding."""
    code, severity, headline = policy.FINDING_TEMPLATES[(item.rung, item.result)]
    return Finding(
        code=code,
        severity=severity,
        headline=headline,
        detail=item.reasons,
        detector_id=item.detector_id,
        rung=item.rung,
        standard_ref=item.standard_ref,
        artifacts=item.artifacts,
    )


def _findings(items: Sequence[Evidence]) -> tuple[Finding, ...]:
    """Return every decision-relevant finding, worst first, then by detector."""
    findings = [
        _to_finding(item)
        for item in items
        if item.rung is not Rung.CONTEXTUAL and (item.rung, item.result) in policy.FINDING_TEMPLATES
    ]
    findings.sort(key=lambda finding: (-finding.severity, finding.detector_id, finding.code))
    return tuple(findings)


def _advisories(items: Sequence[Evidence]) -> tuple[Finding, ...]:
    """Return the Rung 3 context, in the order the detectors reported it."""
    return tuple(_to_finding(item) for item in _matching(items, policy.ADVISORY))


def _not_checked(items: Sequence[Evidence]) -> tuple[str, ...]:
    """Return an explicit account of what this screening did not establish.

    Required by the honesty rule in CLAUDE.md: a check that did not happen is
    reported, never omitted. A missing chip reader, a standard that does not
    govern this document type and a model that failed to load all land here.
    """
    if not items:
        return (_NOTHING_RAN_NOTICE,)
    notices: list[str] = []
    for item in _matching(items, policy.SILENT):
        notices.extend(item.reasons)
    return tuple(notices)
