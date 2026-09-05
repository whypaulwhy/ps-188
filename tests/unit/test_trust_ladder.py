"""Exhaustive tests of the trust ladder.

The ladder is the file that decides what happens to a person at a barrier, so
these tests are written to be read by someone deciding whether to believe it,
not only to be run by CI. They cover:

* every result at every rung, on its own;
* every ordered pair of results, checked against the invariants;
* the two properties the system is judged on — that inference can never clear a
  document, and that adding inference or context can never soften a decision.
"""

from __future__ import annotations

import datetime
import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from core.contracts import (
    RESULTS_BY_RUNG,
    Decision,
    Evidence,
    Result,
    Rung,
    Severity,
    Verdict,
)
from core.trust import decision_severity, resolve
from core.trust.policy import POLICY_VERSION
from tests.support import DECIDED_AT, evidence, provenance

ALL_PAIRS: list[tuple[Rung, Result]] = [
    (rung, result)
    for rung in Rung
    for result in sorted(RESULTS_BY_RUNG[rung], key=lambda item: item.value)
]
"""Every legal (rung, result) combination, in a fixed order."""

SOFT_PAIRS: list[tuple[Rung, Result]] = [
    pair for pair in ALL_PAIRS if pair[0] in (Rung.INFERENCE, Rung.CONTEXTUAL)
]
"""The pairs that may only escalate or advise: Rung 2 and Rung 3."""

EXPECTED_ALONE: dict[tuple[Rung, Result], Decision] = {
    (Rung.CRYPTOGRAPHIC, Result.PROOF_VALID): Decision.CLEARED,
    (Rung.CRYPTOGRAPHIC, Result.PROOF_INVALID): Decision.REJECTED,
    (Rung.CRYPTOGRAPHIC, Result.NO_PROOF_PRESENT): Decision.MANUAL_REVIEW,
    (Rung.DETERMINISTIC, Result.PASS): Decision.MANUAL_REVIEW,
    (Rung.DETERMINISTIC, Result.FAIL): Decision.REJECTED,
    (Rung.DETERMINISTIC, Result.NOT_APPLICABLE): Decision.MANUAL_REVIEW,
    (Rung.INFERENCE, Result.NO_FINDING): Decision.MANUAL_REVIEW,
    (Rung.INFERENCE, Result.SUSPICIOUS): Decision.MANUAL_REVIEW,
    (Rung.INFERENCE, Result.INCONCLUSIVE): Decision.MANUAL_REVIEW,
    (Rung.CONTEXTUAL, Result.FLAG_RAISED): Decision.MANUAL_REVIEW,
    (Rung.CONTEXTUAL, Result.NO_FLAG): Decision.MANUAL_REVIEW,
}
"""What each result decides on its own. Only cryptographic proof clears."""


def decide(*items: Evidence) -> Verdict:
    """Resolve evidence at a fixed timestamp so verdicts are reproducible."""
    return resolve(items, decided_at=DECIDED_AT)


# ---------------------------------------------------------------------------
# The empty case
# ---------------------------------------------------------------------------


def test_no_evidence_is_manual_review() -> None:
    """A screening that checked nothing has established nothing."""
    verdict = decide()

    assert verdict.decision is Decision.MANUAL_REVIEW
    assert verdict.findings == ()
    assert verdict.advisories == ()
    assert verdict.policy_version == POLICY_VERSION


def test_no_evidence_says_so_out_loud() -> None:
    """Silence about a missing check is a defect, so the empty case is explicit."""
    verdict = decide()

    assert verdict.not_checked == ("Nothing about this document was checked.",)
    assert "no checks were run" in verdict.basis[0].lower()


# ---------------------------------------------------------------------------
# Every rung and result, alone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("rung", "result"), ALL_PAIRS, ids=lambda value: str(value))
def test_each_result_alone(rung: Rung, result: Result) -> None:
    """Each result on its own decides exactly what the policy table says it does."""
    verdict = decide(evidence(rung, result))

    assert verdict.decision is EXPECTED_ALONE[(rung, result)]


def test_only_cryptographic_proof_clears_on_its_own() -> None:
    """Exactly one of the eleven results can clear a document by itself."""
    clearing = [pair for pair, decision in EXPECTED_ALONE.items() if decision is Decision.CLEARED]

    assert clearing == [(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)]


# ---------------------------------------------------------------------------
# Every ordered pair
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("first", "second"),
    list(itertools.product(ALL_PAIRS, ALL_PAIRS)),
    ids=lambda value: f"{value[0].name}-{value[1].name}",
)
def test_every_pair_obeys_the_ladder(
    first: tuple[Rung, Result], second: tuple[Rung, Result]
) -> None:
    """For all 121 ordered pairs, the invariants of the ladder hold.

    Three claims are checked at once, which is what makes this exhaustive rather
    than illustrative: a rejection requires authoritative rejecting evidence, a
    clearance requires cryptographic proof and the absence of anything worse,
    and Rung 3 is inert.
    """
    items = (
        evidence(*first, detector_id="a.first"),
        evidence(*second, detector_id="b.second"),
    )
    pairs = {first, second}
    verdict = decide(*items)

    rejecting = pairs & {
        (Rung.CRYPTOGRAPHIC, Result.PROOF_INVALID),
        (Rung.DETERMINISTIC, Result.FAIL),
    }
    escalating = pairs & {(Rung.INFERENCE, Result.SUSPICIOUS)}
    proving = pairs & {(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)}

    if rejecting:
        assert verdict.decision is Decision.REJECTED
    elif escalating:
        assert verdict.decision is Decision.MANUAL_REVIEW
    elif proving:
        assert verdict.decision is Decision.CLEARED
    else:
        assert verdict.decision is Decision.MANUAL_REVIEW


# ---------------------------------------------------------------------------
# Rung 1 FAIL rejects, unconditionally
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("rung", "result"), ALL_PAIRS, ids=lambda value: str(value))
def test_a_rung1_failure_rejects_whatever_else_is_present(rung: Rung, result: Result) -> None:
    """No combination of other evidence can rescue a document that fails a fixed rule."""
    verdict = decide(
        evidence(rung, result, detector_id="other.detector"),
        evidence(Rung.DETERMINISTIC, Result.FAIL, detector_id="rung1.checkdigits"),
    )

    assert verdict.decision is Decision.REJECTED


def test_a_rung1_failure_beats_a_valid_signature() -> None:
    """A genuine signature over a document that breaks a fixed rule is still a rejection.

    This is the fail-closed tie-break. A document can carry an authentic issuer
    signature and still be unusable — for instance if it has expired — and the
    system must not clear it because one authority said yes.
    """
    verdict = decide(
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
        evidence(Rung.DETERMINISTIC, Result.FAIL),
    )

    assert verdict.decision is Decision.REJECTED


def test_an_invalid_signature_rejects() -> None:
    """A signature that is present and does not verify ends the case."""
    verdict = decide(evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_INVALID))

    assert verdict.decision is Decision.REJECTED


# ---------------------------------------------------------------------------
# Rung 2 can never clear
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score", [0.0, 0.01, 0.5, 0.99, 1.0])
def test_inference_never_clears_at_any_score(score: float) -> None:
    """No Rung 2 score clears a document, at either end of the range.

    ``score`` is suspicion, so ``0.0`` is a model expressing total confidence
    that the document is authentic. It still does not clear, because the ladder
    never consults inference when deciding whether to clear.
    """
    verdict = decide(
        evidence(Rung.INFERENCE, Result.NO_FINDING, score=score, uncertainty=0.0),
    )

    assert verdict.decision is Decision.MANUAL_REVIEW


def test_inference_and_context_together_never_clear() -> None:
    """Piling up soft evidence does not add up to a clearance."""
    verdict = decide(
        evidence(
            Rung.INFERENCE, Result.NO_FINDING, detector_id="r2.tamper", score=0.0, uncertainty=0.0
        ),
        evidence(
            Rung.INFERENCE, Result.NO_FINDING, detector_id="r2.face", score=0.0, uncertainty=0.0
        ),
        evidence(Rung.CONTEXTUAL, Result.NO_FLAG, detector_id="r3.watchlist"),
    )

    assert verdict.decision is Decision.MANUAL_REVIEW


def test_a_clearance_cannot_be_constructed_from_inference_alone() -> None:
    """Even bypassing the ladder, the contract refuses a clearance with no authority.

    This is the structural half of the guarantee. If a future policy tried to
    clear on a Rung 2 result, the verdict itself would refuse to exist.
    """
    with pytest.raises(ValidationError, match="CLEARED requires an affirmative"):
        Verdict(
            decision=Decision.CLEARED,
            basis=("A policy that should not exist cleared this.",),
            evidence=(evidence(Rung.INFERENCE, Result.NO_FINDING, score=0.0, uncertainty=0.0),),
            decided_at=DECIDED_AT,
            policy_version="handmade/0",
        )


def test_inference_can_never_reject() -> None:
    """The strongest possible suspicion escalates to a human; it does not decide."""
    verdict = decide(
        evidence(Rung.INFERENCE, Result.SUSPICIOUS, score=1.0, uncertainty=0.0),
    )

    assert verdict.decision is Decision.MANUAL_REVIEW


def test_suspicion_escalates_a_document_that_would_otherwise_clear() -> None:
    """A concern from inference holds back a clearance rather than reversing the proof.

    The valid signature is still recorded as a finding. What changes is that a
    person looks at the case before the traveller proceeds.
    """
    verdict = decide(
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
        evidence(Rung.INFERENCE, Result.SUSPICIOUS, score=0.8, uncertainty=0.2),
    )

    assert verdict.decision is Decision.MANUAL_REVIEW
    assert any(finding.code == "ISSUER_SIGNATURE_VALID" for finding in verdict.findings)


def test_a_deterministic_pass_alone_does_not_clear() -> None:
    """Conforming to a standard is not proof of issuance, so it goes to review."""
    verdict = decide(evidence(Rung.DETERMINISTIC, Result.PASS))

    assert verdict.decision is Decision.MANUAL_REVIEW
    assert "nothing available established" in verdict.basis[0]


# ---------------------------------------------------------------------------
# Rung 3 never decides
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("result", sorted(RESULTS_BY_RUNG[Rung.CONTEXTUAL], key=str))
def test_context_never_changes_a_decision(result: Result) -> None:
    """Adding a contextual signal to a cleared case leaves it cleared."""
    without = decide(evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID))
    with_context = decide(
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
        evidence(Rung.CONTEXTUAL, result),
    )

    assert without.decision is Decision.CLEARED
    assert with_context.decision is Decision.CLEARED


def test_context_is_kept_out_of_the_findings() -> None:
    """Advisories are filed separately so they cannot be read as reasons for the decision."""
    verdict = decide(
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
        evidence(Rung.CONTEXTUAL, Result.FLAG_RAISED),
    )

    assert [finding.rung for finding in verdict.findings] == [Rung.CRYPTOGRAPHIC]
    assert [advisory.rung for advisory in verdict.advisories] == [Rung.CONTEXTUAL]
    assert verdict.advisories[0].severity is Severity.ADVISORY


def test_a_watchlist_hit_alone_decides_nothing() -> None:
    """A flag with no document evidence behind it is still just a flag."""
    verdict = decide(evidence(Rung.CONTEXTUAL, Result.FLAG_RAISED))

    assert verdict.decision is Decision.MANUAL_REVIEW
    assert verdict.findings == ()


# ---------------------------------------------------------------------------
# Monotonicity
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    base=st.lists(st.sampled_from(ALL_PAIRS), max_size=5),
    extra=st.lists(st.sampled_from(SOFT_PAIRS), max_size=5),
)
def test_soft_evidence_never_softens_a_decision(
    base: list[tuple[Rung, Result]], extra: list[tuple[Rung, Result]]
) -> None:
    """Adding Rung 2 or Rung 3 evidence never moves a case toward CLEARED.

    This is the monotonicity rule stated as a property over arbitrary evidence
    sets rather than as a handful of examples.
    """
    before = [evidence(*pair, detector_id=f"base.d{index}") for index, pair in enumerate(base)]
    after = [
        *before,
        *[evidence(*pair, detector_id=f"extra.d{index}") for index, pair in enumerate(extra)],
    ]

    assert decision_severity(resolve(after, decided_at=DECIDED_AT).decision) >= decision_severity(
        resolve(before, decided_at=DECIDED_AT).decision
    )


@settings(max_examples=200, deadline=None)
@given(items=st.lists(st.sampled_from(ALL_PAIRS), max_size=6))
def test_clearance_always_rests_on_proof(items: list[tuple[Rung, Result]]) -> None:
    """However the evidence is combined, a clearance implies cryptographic proof."""
    verdict = resolve(
        [evidence(*pair, detector_id=f"d.x{index}") for index, pair in enumerate(items)],
        decided_at=DECIDED_AT,
    )

    if verdict.decision is Decision.CLEARED:
        assert (Rung.CRYPTOGRAPHIC, Result.PROOF_VALID) in set(items)


@settings(max_examples=200, deadline=None)
@given(items=st.lists(st.sampled_from(ALL_PAIRS), min_size=1, max_size=6))
def test_rejection_always_rests_on_an_authoritative_failure(
    items: list[tuple[Rung, Result]],
) -> None:
    """However the evidence is combined, a rejection implies a Rung 0 or Rung 1 failure."""
    verdict = resolve(
        [evidence(*pair, detector_id=f"d.x{index}") for index, pair in enumerate(items)],
        decided_at=DECIDED_AT,
    )

    if verdict.decision is Decision.REJECTED:
        assert set(items) & {
            (Rung.CRYPTOGRAPHIC, Result.PROOF_INVALID),
            (Rung.DETERMINISTIC, Result.FAIL),
        }


# ---------------------------------------------------------------------------
# What the verdict carries
# ---------------------------------------------------------------------------


def test_not_checked_reports_everything_that_established_nothing() -> None:
    """A missing signature, an inapplicable standard and an unavailable model are all reported."""
    verdict = decide(
        evidence(
            Rung.CRYPTOGRAPHIC,
            Result.NO_PROOF_PRESENT,
            reasons=("This document type carries no digital signature to check.",),
        ),
        evidence(
            Rung.DETERMINISTIC,
            Result.NOT_APPLICABLE,
            reasons=("This document has no machine readable zone, so it was not checked.",),
        ),
        evidence(
            Rung.INFERENCE,
            Result.INCONCLUSIVE,
            reasons=("The alteration detection model did not load, so no check was made.",),
        ),
    )

    assert len(verdict.not_checked) == 3
    assert "did not load" in verdict.not_checked[2]


def test_silent_results_produce_no_findings() -> None:
    """A check that did not happen is not shown as a check that passed."""
    verdict = decide(evidence(Rung.INFERENCE, Result.INCONCLUSIVE))

    assert verdict.findings == ()
    assert verdict.not_checked != ()


def test_findings_are_ordered_worst_first() -> None:
    """The console gets findings in the order an officer should read them."""
    verdict = decide(
        evidence(
            Rung.INFERENCE, Result.NO_FINDING, detector_id="z.tamper", score=0.1, uncertainty=0.1
        ),
        evidence(Rung.DETERMINISTIC, Result.FAIL, detector_id="a.expiry"),
        evidence(
            Rung.INFERENCE, Result.SUSPICIOUS, detector_id="m.splice", score=0.7, uncertainty=0.2
        ),
    )

    assert [finding.severity for finding in verdict.findings] == [
        Severity.CRITICAL,
        Severity.CONCERN,
        Severity.INFO,
    ]


def test_the_basis_repeats_the_reasons_the_officer_needs() -> None:
    """The justification names the actual failure, not just the outcome."""
    verdict = decide(
        evidence(
            Rung.DETERMINISTIC,
            Result.FAIL,
            reasons=("The date of birth printed on the card does not match its coded form.",),
        )
    )

    assert verdict.basis[0].startswith("This document was rejected")
    assert "date of birth" in verdict.basis[1]


def test_evidence_is_carried_through_untouched() -> None:
    """The audit record holds what the detectors said, not a summary of it."""
    item = evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)
    verdict = decide(item)

    assert verdict.evidence == (item,)


def test_provenance_is_carried_onto_the_verdict() -> None:
    """A decision can be tied back to the exact bytes it was made about."""
    record = provenance()
    verdict = resolve(
        [evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)],
        provenance=record,
        decided_at=DECIDED_AT,
    )

    assert verdict.provenance == record


def test_the_timestamp_defaults_to_now() -> None:
    """Omitting the timestamp stamps the current time rather than leaving it blank."""
    before = datetime.datetime.now(datetime.UTC)
    verdict = resolve([evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)])
    after = datetime.datetime.now(datetime.UTC)

    assert before <= verdict.decided_at <= after


def test_findings_carry_the_standard_that_makes_them_defensible() -> None:
    """A finding an officer acts on can always be traced to a published clause."""
    verdict = decide(evidence(Rung.DETERMINISTIC, Result.FAIL))

    assert verdict.findings[0].standard_ref == "ICAO Doc 9303 Part 3 s.4.2.2"


def test_findings_carry_their_exhibits() -> None:
    """Heatmaps and crops reach the console attached to the finding that produced them."""
    verdict = decide(
        evidence(
            Rung.INFERENCE,
            Result.SUSPICIOUS,
            score=0.9,
            uncertainty=0.1,
            artifacts=("artifacts/case-1/heatmap.png",),
        )
    )

    assert verdict.findings[0].artifacts == ("artifacts/case-1/heatmap.png",)
