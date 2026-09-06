"""The report an officer reads, checked against the honesty rule in CLAUDE.md.

"The officer console and every generated report must state what was NOT
checked. Silence about a missing check is a defect, not a clean result."

That is a testable claim, and this file tests it as one: the section is required
on every decision, including clearances, including cases where nothing was left
unchecked, and every line the verdict carries has to survive into the output.

The other half is about what must never appear. Findings carry no score by
contract; this checks the renderer does not reach around that into the raw
evidence, because a number on the page invites an officer to weigh 0.31 against
0.62 instead of reading the sentences.
"""

from __future__ import annotations

import pytest

from core.contracts import Decision, Result, Rung, Verdict
from core.trust.ladder import resolve
from explain.renderer import (
    CLEARANCE_CAVEAT,
    CONTEXT_HEADING,
    NOT_CHECKED_HEADING,
    NOTHING_UNCHECKED,
    WIDTH,
    render_verdict,
)
from tests.support import DECIDED_AT, evidence, provenance


def verdict_for(*pairs: tuple[Rung, Result]) -> Verdict:
    """Resolve a verdict from one piece of evidence per rung and result given."""
    return resolve(
        [evidence(rung, result) for rung, result in pairs],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )


CLEARED = verdict_for((Rung.CRYPTOGRAPHIC, Result.PROOF_VALID))
"""A clearance with nothing unchecked: the hardest case for the honesty rule."""

REJECTED = verdict_for(
    (Rung.DETERMINISTIC, Result.FAIL), (Rung.CRYPTOGRAPHIC, Result.NO_PROOF_PRESENT)
)
"""A rejection that also failed to check something."""

REVIEWED = verdict_for((Rung.INFERENCE, Result.SUSPICIOUS), (Rung.CONTEXTUAL, Result.FLAG_RAISED))
"""An escalation carrying a Rung 3 advisory."""

NOTHING_RAN = resolve([], decided_at=DECIDED_AT)
"""A case where no detector ran at all, and no provenance was recorded."""

EVERY_VERDICT = [CLEARED, REJECTED, REVIEWED, NOTHING_RAN]
"""Every shape of verdict the ladder can produce."""


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_every_report_states_what_was_not_checked(verdict: Verdict) -> None:
    """The honesty rule, as a test. No decision is exempt, clearances included."""
    assert NOT_CHECKED_HEADING in render_verdict(verdict)


def test_the_section_says_so_in_words_when_nothing_was_unchecked() -> None:
    """An empty section that vanishes teaches an officer to stop looking for it."""
    report = render_verdict(CLEARED)

    assert CLEARED.not_checked == ()
    assert NOTHING_UNCHECKED in " ".join(report.split())


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_no_unchecked_line_is_dropped(verdict: Verdict) -> None:
    """Every notice the verdict carries reaches the page, whole."""
    flattened = " ".join(render_verdict(verdict).split())

    for notice in verdict.not_checked:
        assert " ".join(notice.split()) in flattened


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_no_finding_is_dropped(verdict: Verdict) -> None:
    """The same for findings: the report is the record, not a summary of it."""
    flattened = " ".join(render_verdict(verdict).split())

    for finding in verdict.findings:
        assert " ".join(finding.headline.split()) in flattened


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_no_score_reaches_the_page(verdict: Verdict) -> None:
    """Scores stay in the evidence record. On screen they invite arithmetic."""
    report = render_verdict(verdict).lower()

    assert "score" not in report
    assert "uncertainty" not in report
    for item in verdict.evidence:
        if item.score is not None:
            assert str(item.score) not in report


def test_a_suspicious_case_really_does_carry_a_score() -> None:
    """Otherwise the test above would be passing on an empty premise."""
    assert any(item.score is not None for item in REVIEWED.evidence)


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_the_decision_is_stated_in_words(verdict: Verdict) -> None:
    """An officer should not have to know what an enum member means."""
    report = render_verdict(verdict)

    assert "DECISION:" in report
    assert verdict.decision.value.replace("_", " ") in report


def test_a_clearance_says_what_it_does_not_mean() -> None:
    """The system verified a signature. It did not identify the person holding it."""
    assert CLEARANCE_CAVEAT in " ".join(render_verdict(CLEARED).split())


@pytest.mark.parametrize("verdict", [REJECTED, REVIEWED, NOTHING_RAN])
def test_the_clearance_caveat_appears_only_on_a_clearance(verdict: Verdict) -> None:
    """Boilerplate on every page is boilerplate nobody reads."""
    assert verdict.decision is not Decision.CLEARED
    assert CLEARANCE_CAVEAT not in " ".join(render_verdict(verdict).split())


def test_context_is_labelled_as_not_having_decided_anything() -> None:
    """Rung 3 never decides, and the heading is where an officer learns that."""
    report = render_verdict(REVIEWED)

    assert CONTEXT_HEADING in report
    assert "did not affect this decision" in CONTEXT_HEADING.lower()


def test_a_context_flag_reaches_the_page() -> None:
    """Labelled as advisory, but still shown: the officer decides what it means."""
    flattened = " ".join(render_verdict(REVIEWED).split())

    for advisory in REVIEWED.advisories:
        assert any(" ".join(reason.split()) in flattened for reason in advisory.detail)


def test_a_report_without_context_omits_the_context_heading() -> None:
    """A heading over nothing reads as though something was withheld."""
    assert CONTEXT_HEADING not in render_verdict(CLEARED)


def test_a_case_without_provenance_still_renders() -> None:
    """A verdict can be resolved without a capture, and must still print."""
    report = render_verdict(NOTHING_RAN)

    assert "not recorded" in report
    assert "no artefact recorded" in report


def test_the_document_digest_is_printed_whole() -> None:
    """It is what ties the report to the bytes that were screened."""
    assert provenance().sha256 in render_verdict(REJECTED)


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_the_report_fits_its_width(verdict: Verdict) -> None:
    """Fixed width, so the same report prints identically on any terminal."""
    for line in render_verdict(verdict).splitlines():
        assert len(line) <= WIDTH, line


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_rendering_is_deterministic(verdict: Verdict) -> None:
    """Two renderings must be byte-identical, or a report cannot be digested."""
    assert render_verdict(verdict) == render_verdict(verdict)


@pytest.mark.parametrize("verdict", EVERY_VERDICT)
def test_the_standard_behind_a_finding_is_shown(verdict: Verdict) -> None:
    """`standard_ref` is what makes a decision defensible when it is challenged."""
    report = render_verdict(verdict)

    for finding in verdict.findings:
        if finding.standard_ref:
            assert finding.standard_ref in report
