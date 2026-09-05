"""Tests of the evidence contract itself.

The contract's job is to make invalid states unconstructable. These tests
mostly assert that things *fail*, one rule at a time, because that is where the
value is: a detector cannot overstate its authority even by accident.
"""

from __future__ import annotations

import datetime

import pytest
from pydantic import ValidationError

from core.contracts import (
    RESULTS_BY_RUNG,
    SCORED_RUNGS,
    Decision,
    Evidence,
    Finding,
    Result,
    Rung,
    Severity,
    Verdict,
)
from core.trust import decision_severity
from tests.support import DECIDED_AT, DIGEST, evidence, provenance

NAIVE = datetime.datetime(2026, 1, 1, 12, 0)  # deliberately naive


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


def test_rung_order_puts_proof_above_inference() -> None:
    """A smaller rung number means more authority, which the ladder relies on."""
    assert Rung.CRYPTOGRAPHIC < Rung.DETERMINISTIC < Rung.INFERENCE < Rung.CONTEXTUAL


def test_result_sets_do_not_overlap() -> None:
    """A result value identifies its rung, so Rung 2 cannot borrow Rung 0's vocabulary."""
    seen: set[Result] = set()
    for results in RESULTS_BY_RUNG.values():
        assert not (seen & results)
        seen |= results

    assert seen == set(Result)


def test_only_inference_may_carry_numbers() -> None:
    """Exactly one rung is allowed to produce a score."""
    assert sorted(SCORED_RUNGS) == [Rung.INFERENCE]


def test_decisions_are_ordered_worst_last() -> None:
    """The severity order is what monotonicity is stated against."""
    assert (
        decision_severity(Decision.CLEARED)
        < decision_severity(Decision.MANUAL_REVIEW)
        < decision_severity(Decision.REJECTED)
    )


def test_severity_is_ordered() -> None:
    """Findings sort by severity, so the order has to be meaningful."""
    assert Severity.INFO < Severity.ADVISORY < Severity.CONCERN < Severity.CRITICAL


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_valid_evidence_is_frozen() -> None:
    """Evidence is a record of what happened and cannot be edited afterwards."""
    item = evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)

    with pytest.raises(ValidationError):
        item.result = Result.PROOF_INVALID  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    """A typo in a field name fails loudly instead of being silently dropped."""
    with pytest.raises(ValidationError):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, confidence=0.9)


@pytest.mark.parametrize("bad", ["Rung0.Detector", "0rung.detector", "rung0..detector", "rung 0"])
def test_detector_id_must_be_a_dotted_lowercase_identifier(bad: str) -> None:
    """Identifiers end up as keys in the audit log, so their shape is pinned."""
    with pytest.raises(ValidationError, match="dotted lowercase identifier"):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, detector_id=bad)


@pytest.mark.parametrize("bad", ["A" * 64, "g" * 64, "abc"])
def test_input_digest_must_be_lowercase_hex(bad: str) -> None:
    """Digests are compared as strings, so the encoding is fixed."""
    with pytest.raises(ValidationError):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, input_digest=bad)


def test_reasons_cannot_be_empty() -> None:
    """Evidence with nothing to tell the officer is not evidence."""
    with pytest.raises(ValidationError):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, reasons=())


def test_reasons_cannot_be_blank() -> None:
    """A whitespace reason would render as an empty line on the console."""
    with pytest.raises(ValidationError, match="must contain text"):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, reasons=("   ",))


@pytest.mark.parametrize(
    ("rung", "result"),
    [
        (Rung.CRYPTOGRAPHIC, Result.PASS),
        (Rung.DETERMINISTIC, Result.PROOF_VALID),
        (Rung.INFERENCE, Result.PROOF_VALID),
        (Rung.CONTEXTUAL, Result.FAIL),
    ],
)
def test_a_rung_cannot_report_another_rungs_result(rung: Rung, result: Result) -> None:
    """A model cannot claim to have produced a proof."""
    with pytest.raises(ValidationError, match="is not permitted at"):
        evidence(rung, result)


@pytest.mark.parametrize(
    ("rung", "result"),
    [
        (Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
        (Rung.DETERMINISTIC, Result.PASS),
        (Rung.CONTEXTUAL, Result.FLAG_RAISED),
    ],
)
def test_proof_and_context_cannot_carry_a_score(rung: Rung, result: Result) -> None:
    """Attaching a number to proof would invite it to be weighed against a model's number."""
    with pytest.raises(ValidationError, match="must not carry a score"):
        evidence(rung, result, score=0.9)


def test_proof_cannot_carry_an_uncertainty_either() -> None:
    """The rule covers uncertainty on its own, not only score."""
    with pytest.raises(ValidationError, match="must not carry a score"):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, uncertainty=0.1)


def test_an_inconclusive_result_cannot_carry_a_number() -> None:
    """A model that could not answer must not leave a number behind to be misread."""
    with pytest.raises(ValidationError, match="inconclusive result must not carry"):
        evidence(Rung.INFERENCE, Result.INCONCLUSIVE, score=0.5, uncertainty=0.5)


def test_an_inconclusive_result_needs_no_numbers() -> None:
    """The normal unavailable-model case is valid and carries only a reason."""
    item = evidence(Rung.INFERENCE, Result.INCONCLUSIVE)

    assert item.score is None
    assert item.uncertainty is None


@pytest.mark.parametrize(
    "missing", [{"score": None}, {"uncertainty": None}, {"score": None, "uncertainty": None}]
)
def test_a_conclusive_inference_needs_both_numbers(missing: dict[str, None]) -> None:
    """A score without an uncertainty is a claim without a caveat."""
    with pytest.raises(ValidationError, match="requires both a score and an uncertainty"):
        evidence(Rung.INFERENCE, Result.SUSPICIOUS, **missing)


@pytest.mark.parametrize("rung", [Rung.CRYPTOGRAPHIC, Rung.DETERMINISTIC])
def test_authoritative_evidence_must_cite_a_standard(rung: Rung) -> None:
    """Evidence that can decide a case has to say which rule it applied."""
    result = Result.PROOF_VALID if rung is Rung.CRYPTOGRAPHIC else Result.PASS

    with pytest.raises(ValidationError, match="must cite a standard_ref"):
        evidence(rung, result, standard_ref=None)


def test_an_empty_standard_reference_is_not_a_citation() -> None:
    """An empty string is treated as a missing citation, not a present one."""
    with pytest.raises(ValidationError, match="must cite a standard_ref"):
        evidence(Rung.DETERMINISTIC, Result.PASS, standard_ref="")


def test_inference_needs_no_standard_reference() -> None:
    """There is no published clause behind a learned model, and pretending otherwise would lie."""
    item = evidence(Rung.INFERENCE, Result.SUSPICIOUS)

    assert item.standard_ref is None


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_a_score_outside_the_unit_interval_is_rejected(score: float) -> None:
    """Suspicion is defined on [0, 1]; anything else is a bug in the detector."""
    with pytest.raises(ValidationError):
        evidence(Rung.INFERENCE, Result.SUSPICIOUS, score=score)


def test_runtime_cannot_be_negative() -> None:
    """A negative duration would corrupt any later performance measurement."""
    with pytest.raises(ValidationError):
        evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID, runtime_ms=-1.0)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_valid_provenance_records_the_capture() -> None:
    """The ordinary case builds cleanly."""
    record = provenance()

    assert record.sha256 == DIGEST
    assert record.processing_chain == ()


def test_provenance_digest_must_be_lowercase_hex() -> None:
    """The digest identifies the exact bytes screened, so its form is pinned."""
    with pytest.raises(ValidationError, match="64 lowercase hexadecimal"):
        provenance(sha256="Z" * 64)


@pytest.mark.parametrize("field", ["captured_at", "received_at"])
def test_provenance_timestamps_must_carry_a_timezone(field: str) -> None:
    """A naive timestamp in an audit record cannot be placed on a timeline."""
    with pytest.raises(ValidationError, match="timezone aware"):
        provenance(**{field: NAIVE})


def test_custody_cannot_precede_capture() -> None:
    """Receiving an artefact before it was captured means the record is wrong."""
    with pytest.raises(ValidationError, match="cannot precede"):
        provenance(received_at=DECIDED_AT - datetime.timedelta(seconds=1))


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def test_a_finding_needs_a_readable_headline() -> None:
    """The headline is the sentence an officer reads first."""
    with pytest.raises(ValidationError, match="must contain text"):
        Finding(
            code="X",
            severity=Severity.INFO,
            headline="   ",
            detector_id="a.b",
            rung=Rung.INFERENCE,
        )


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


def test_a_verdict_needs_a_timezone_aware_timestamp() -> None:
    """Decisions are audited against a timeline."""
    with pytest.raises(ValidationError, match="timezone aware"):
        Verdict(
            decision=Decision.MANUAL_REVIEW,
            basis=("Sent for review.",),
            decided_at=NAIVE,
            policy_version="test/1",
        )


def test_a_verdict_needs_a_basis() -> None:
    """Every decision says why, in words, including the ones nobody will read."""
    with pytest.raises(ValidationError):
        Verdict(
            decision=Decision.MANUAL_REVIEW,
            basis=(),
            decided_at=DECIDED_AT,
            policy_version="test/1",
        )


def test_a_blank_basis_sentence_is_rejected() -> None:
    """Whitespace is not an explanation."""
    with pytest.raises(ValidationError, match="must contain text"):
        Verdict(
            decision=Decision.MANUAL_REVIEW,
            basis=("  ",),
            decided_at=DECIDED_AT,
            policy_version="test/1",
        )


def test_a_clearance_may_rest_on_a_deterministic_pass() -> None:
    """The contract's floor admits Rung 1; the current ladder policy is stricter than that."""
    verdict = Verdict(
        decision=Decision.CLEARED,
        basis=("Cleared under a policy that trusts deterministic conformance.",),
        evidence=(evidence(Rung.DETERMINISTIC, Result.PASS),),
        decided_at=DECIDED_AT,
        policy_version="hypothetical/1",
    )

    assert verdict.decision is Decision.CLEARED


def test_a_clearance_with_no_evidence_at_all_is_refused() -> None:
    """Nothing cannot clear anything."""
    with pytest.raises(ValidationError, match="CLEARED requires an affirmative"):
        Verdict(
            decision=Decision.CLEARED,
            basis=("Cleared on nothing.",),
            decided_at=DECIDED_AT,
            policy_version="test/1",
        )


def test_advisories_must_be_contextual() -> None:
    """A decision-bearing finding cannot be hidden in the advisory list."""
    finding = Finding(
        code="STANDARD_CHECK_FAILED",
        severity=Severity.CRITICAL,
        headline="A fixed rule was broken.",
        detector_id="rung1.checkdigits",
        rung=Rung.DETERMINISTIC,
    )

    with pytest.raises(ValidationError, match="advisories may only hold"):
        Verdict(
            decision=Decision.MANUAL_REVIEW,
            basis=("Sent for review.",),
            advisories=(finding,),
            decided_at=DECIDED_AT,
            policy_version="test/1",
        )


def test_context_cannot_be_promoted_into_the_findings() -> None:
    """A watchlist hit cannot be dressed up as a reason for the decision."""
    finding = Finding(
        code="CONTEXT_FLAG",
        severity=Severity.ADVISORY,
        headline="Seen at another checkpoint this week.",
        detector_id="rung3.repeat_identity",
        rung=Rung.CONTEXTUAL,
    )

    with pytest.raises(ValidationError, match="belong in advisories"):
        Verdict(
            decision=Decision.MANUAL_REVIEW,
            basis=("Sent for review.",),
            findings=(finding,),
            decided_at=DECIDED_AT,
            policy_version="test/1",
        )


def test_a_verdict_is_frozen() -> None:
    """The audit record cannot be edited after the fact."""
    verdict = Verdict(
        decision=Decision.MANUAL_REVIEW,
        basis=("Sent for review.",),
        decided_at=DECIDED_AT,
        policy_version="test/1",
    )

    with pytest.raises(ValidationError):
        verdict.decision = Decision.CLEARED  # type: ignore[misc]


def test_evidence_round_trips_through_json() -> None:
    """The whole record has to survive being written to the ledger and read back."""
    item = evidence(Rung.INFERENCE, Result.SUSPICIOUS, score=0.7, uncertainty=0.2)

    assert Evidence.model_validate_json(item.model_dump_json()) == item
