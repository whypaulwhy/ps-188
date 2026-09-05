"""Tests of the golden harness itself.

A harness that cannot fail is worse than no harness: it turns an empty
guarantee into a green tick. Phase 1 registers no detectors, so the comparison
logic would otherwise never execute. These tests exercise it directly.
"""

from __future__ import annotations

import pytest

from core.contracts import Evidence, Result, Rung
from tests.golden.harness import assert_matches, comparable, differences
from tests.support import DIGEST


def evidence(**overrides: object) -> Evidence:
    """Build a valid Rung 1 evidence record with a fixed shape."""
    fields: dict[str, object] = {
        "detector_id": "rung1.mrz_checkdigits",
        "rung": Rung.DETERMINISTIC,
        "result": Result.PASS,
        "reasons": ("The strip is self-consistent.",),
        "standard_ref": "ICAO Doc 9303 Part 3 s.4.2.2",
        "runtime_ms": 1.0,
        "model_version": "mrz/1.0.0",
        "input_digest": DIGEST,
    }
    fields.update(overrides)
    return Evidence(**fields)


def test_identical_evidence_matches() -> None:
    """The ordinary passing case."""
    assert_matches((evidence(),), (evidence(),), case_id="t")


def test_runtime_is_ignored() -> None:
    """A detector that runs faster today has not changed behaviour."""
    assert_matches((evidence(runtime_ms=0.1),), (evidence(runtime_ms=999.0),), case_id="t")


def test_model_version_is_ignored() -> None:
    """Versioning a detector must not invalidate the whole corpus at once."""
    assert_matches(
        (evidence(model_version="mrz/2.0.0"),), (evidence(model_version="any"),), case_id="t"
    )


def test_a_changed_result_fails() -> None:
    """The thing the harness exists to catch."""
    with pytest.raises(AssertionError, match="result"):
        assert_matches((evidence(result=Result.FAIL),), (evidence(),), case_id="t")


def test_changed_officer_wording_fails() -> None:
    """Text an officer reads is pinned, so it cannot drift without a decision."""
    with pytest.raises(AssertionError, match="reasons"):
        assert_matches((evidence(reasons=("Something else.",)),), (evidence(),), case_id="t")


def test_a_changed_standard_reference_fails() -> None:
    """The clause a decision rests on is part of the golden."""
    with pytest.raises(AssertionError, match="standard_ref"):
        assert_matches(
            (evidence(standard_ref="ICAO Doc 9303 Part 4 s.1"),), (evidence(),), case_id="t"
        )


def test_extra_evidence_fails() -> None:
    """A detector that starts reporting more than it used to has changed."""
    with pytest.raises(AssertionError, match="expected 1 piece"):
        assert_matches((evidence(), evidence()), (evidence(),), case_id="t")


def test_missing_evidence_fails() -> None:
    """A detector that goes quiet is a defect, not a pass."""
    with pytest.raises(AssertionError, match="detector produced 0"):
        assert_matches((), (evidence(),), case_id="t")


def test_order_is_significant() -> None:
    """Evidence order reaches the officer console, so it is part of the expectation."""
    first = evidence(detector_id="a.one")
    second = evidence(detector_id="b.two")

    with pytest.raises(AssertionError, match="detector_id"):
        assert_matches((second, first), (first, second), case_id="t")


def test_the_failure_report_names_the_case_and_every_difference() -> None:
    """A golden failure has to be readable without opening the fixture."""
    with pytest.raises(AssertionError) as raised:
        assert_matches(
            (evidence(result=Result.FAIL, reasons=("Different.",)),),
            (evidence(),),
            case_id="td3-ind-specimen",
        )

    message = str(raised.value)
    assert "td3-ind-specimen" in message
    assert "result" in message
    assert "reasons" in message


def test_comparable_drops_only_the_two_volatile_fields() -> None:
    """The exclusion list is deliberately tiny and must stay that way."""
    dropped = set(evidence().model_dump(mode="json")) - set(comparable(evidence()))

    assert dropped == {"runtime_ms", "model_version"}


def test_differences_is_empty_for_a_match() -> None:
    """The reporting function agrees with the assertion it backs."""
    assert differences((evidence(),), (evidence(),)) == []
