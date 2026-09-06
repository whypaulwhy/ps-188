"""Turning a verdict into the page an officer reads, with nothing left out.

Deterministic templates over the verdict. No model is involved and none may be:
a language model rephrasing a decision can drop a qualifier, and the qualifiers
are the part that matters. :mod:`explain.llm_client` exists to rephrase text
this module has already produced, and it decides nothing.

Three properties this module is responsible for.

**The unchecked section is unconditional.** CLAUDE.md says silence about a
missing check is a defect, so the heading is emitted on every case, including
clearances, and including cases where nothing was left unchecked — in which
case it says that in words rather than vanishing. A section that disappears
when it is empty teaches an officer to stop looking for it.

**No score reaches the page.** Findings carry none by contract, and this
renderer never reads one from the evidence. A number on screen invites an
officer to weigh 0.31 against 0.62, which is the reasoning the trust ladder
exists to replace.

**A clearance is described for what it is.** The system can verify that an
issuing authority signed a document. It cannot verify that the person holding
it is its subject. A cleared report says so, because an officer reading the
word "cleared" will otherwise supply the stronger meaning themselves.
"""

from __future__ import annotations

import textwrap
from typing import Final

from core.contracts import Decision, Severity, Verdict

WIDTH: Final[int] = 78
"""Wrap width. Fixed so two renderings of one verdict are byte-identical."""

NOT_CHECKED_HEADING: Final[str] = "WHAT WAS NOT CHECKED"
"""Exported so a test can require it without restating the literal."""

FOUND_HEADING: Final[str] = "WHAT WAS FOUND"
"""Heading for the findings section."""

CONTEXT_HEADING: Final[str] = "CONTEXT, WHICH DID NOT AFFECT THIS DECISION"
"""Heading for Rung 3 advisories. The disclaimer is in the heading, not a footnote."""

WHY_HEADING: Final[str] = "WHY"
"""Heading for the plain-language basis."""

DECISION_LINES: Final[dict[Decision, str]] = {
    Decision.CLEARED: "CLEARED - the document may proceed",
    Decision.MANUAL_REVIEW: "MANUAL REVIEW - a person must examine this document",
    Decision.REJECTED: "REJECTED - this document must not be accepted",
}
"""Plain-language expansion of each decision. An officer should not need the enum."""

CLEARANCE_CAVEAT: Final[str] = (
    "This clearance means the issuing authority's signature on the document was "
    "verified. It is not a statement about the person presenting it."
)
"""Printed on every clearance. The word on its own reads stronger than the fact."""

NOTHING_UNCHECKED: Final[str] = (
    "No check reported that it could not be completed. That is not the same as "
    "everything having been checked: only the checks listed above were run."
)
"""What the unchecked section says when it is empty. It never says nothing."""

SEVERITY_TAGS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "[SERIOUS]",
    Severity.CONCERN: "[LOOK AT THIS]",
    Severity.ADVISORY: "[CONTEXT]",
    Severity.INFO: "[CHECKED]",
}
"""Words rather than colours, so the report survives being printed in black and white."""


def _wrap(text: str, *, indent: str = "  ", first: str | None = None) -> list[str]:
    """Wrap one sentence to the fixed width, returning its lines."""
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first if first is not None else indent,
        subsequent_indent=indent,
    ) or [indent.rstrip()]


def _field(label: str, value: str) -> list[str]:
    """Render one header field, dot-led so the values line up when scanned.

    A value that will not fit drops to its own line rather than wrapping. A
    digest broken across two lines cannot be selected and pasted, which is the
    only thing anyone ever does with one.
    """
    leader = f"{label} {'.' * max(1, 18 - len(label))}"
    line = f"{leader} {value}"
    return [line] if len(line) <= WIDTH else [leader, f"    {value}"]


def _header(verdict: Verdict) -> list[str]:
    """Render the identifying block: what this is, and which case it belongs to."""
    provenance = verdict.provenance
    return [
        "SENTINEL ID - SCREENING REPORT",
        "=" * 30,
        "",
        f"DECISION: {DECISION_LINES[verdict.decision]}",
        "",
        *_field("Case", provenance.source_id if provenance else "not recorded"),
        *_field("Checkpoint", provenance.checkpoint_id if provenance else "not recorded"),
        *_field("Decided", verdict.decided_at.isoformat()),
        *_field("Policy", verdict.policy_version),
        *_field("Document digest", provenance.sha256 if provenance else "no artefact recorded"),
    ]


def _why(verdict: Verdict) -> list[str]:
    """Render the plain-language basis, plus the caveat that a clearance needs."""
    lines = ["", WHY_HEADING]
    for sentence in verdict.basis:
        lines.extend(_wrap(sentence, indent="    ", first="  - "))
    if verdict.decision is Decision.CLEARED:
        lines.append("")
        lines.extend(_wrap(CLEARANCE_CAVEAT, indent="  "))
    return lines


def _findings(verdict: Verdict) -> list[str]:
    """Render what was found, worst first, each with the clause behind it."""
    lines = ["", FOUND_HEADING]
    if not verdict.findings:
        lines.extend(_wrap("No check produced a result to report.", indent="  "))
        return lines
    for finding in verdict.findings:
        lines.append("")
        lines.extend(_wrap(f"{SEVERITY_TAGS[finding.severity]} {finding.headline}", indent="  "))
        for reason in finding.detail:
            lines.extend(_wrap(reason, indent="      ", first="    - "))
        if finding.standard_ref:
            lines.extend(_wrap(f"Rule: {finding.standard_ref}", indent="      ", first="    "))
        for artifact in finding.artifacts:
            lines.extend(_wrap(f"Exhibit: {artifact}", indent="      ", first="    "))
    return lines


def _not_checked(verdict: Verdict) -> list[str]:
    """Render the unchecked section. Emitted on every case without exception."""
    lines = ["", NOT_CHECKED_HEADING]
    if not verdict.not_checked:
        lines.extend(_wrap(NOTHING_UNCHECKED, indent="  "))
        return lines
    for notice in verdict.not_checked:
        lines.extend(_wrap(notice, indent="    ", first="  - "))
    return lines


def _context(verdict: Verdict) -> list[str]:
    """Render Rung 3 advisories, under a heading that says they decided nothing.

    The detector's own sentences are the bullets, not the template headline: the
    headline for a contextual flag says only that it did not affect the
    decision, which the heading has already said. What the officer needs is the
    thing that was noticed.
    """
    if not verdict.advisories:
        return []
    lines = ["", CONTEXT_HEADING]
    for advisory in verdict.advisories:
        for sentence in advisory.detail or (advisory.headline,):
            lines.extend(_wrap(sentence, indent="    ", first="  - "))
    return lines


def render_verdict(verdict: Verdict) -> str:
    """Render a verdict as the officer-facing report.

    Args:
        verdict: The resolved case.

    Returns:
        Plain text, wrapped to a fixed width. The same verdict always renders
        to the same bytes, so a report can be digested and compared.
    """
    lines: list[str] = [
        *_header(verdict),
        *_why(verdict),
        *_findings(verdict),
        *_not_checked(verdict),
        *_context(verdict),
        "",
    ]
    return "\n".join(lines)
