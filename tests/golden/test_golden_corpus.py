"""The committed fixture corpus, and what it is allowed to contain.

Most of these tests run today even though no detector exists. They check that
every fixture is licensed and traceable, that every committed expectation is a
legal `Evidence` record, and that no expectation puts jargon in front of an
officer. The one test that needs a detector reports as pending until phase 5
registers it.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from core.contracts import Evidence, Result, Rung
from detectors import Detector
from detectors.rung0_crypto import digilocker_xml_sig, pdf_pkcs7
from detectors.rung0_crypto.trust_store import TrustStore
from tests.golden.harness import (
    JARGON,
    GoldenCase,
    assert_matches,
    discover_cases,
    load_vectors,
)

BUILDERS: dict[str, Callable[[TrustStore], Detector]] = {
    "rung0.digilocker_xml_sig": digilocker_xml_sig.build,
    "rung0.pdf_pkcs7": pdf_pkcs7.build,
}
"""How to construct each implemented detector. A detector absent here is pending."""

CASES: tuple[GoldenCase, ...] = discover_cases()
IDS: list[str] = [case.case_id for case in CASES]


def test_the_corpus_is_not_empty() -> None:
    """A discovery bug that found nothing would make every test below vacuous."""
    assert len(CASES) >= 6


def test_the_corpus_covers_the_documents_that_cannot_be_verified() -> None:
    """Most crossings on these borders present a document with nothing to check.

    The corpus has to contain those cases, because `NOT_APPLICABLE` is the
    answer the system will give most often and it is the answer most likely to
    be quietly turned into a pass by a careless implementation.
    """
    inapplicable = [
        case
        for case in CASES
        if any(item.result is Result.NOT_APPLICABLE for item in case.expected)
    ]

    assert len(inapplicable) >= 3


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_every_fixture_is_licensed_and_traceable(case: GoldenCase) -> None:
    """A fixture nobody can account for cannot be committed to this repository."""
    assert case.licence.strip()
    assert case.provenance.strip()
    assert case.description.strip()


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_the_fixture_file_matches_its_declared_digest(case: GoldenCase) -> None:
    """A fixture edited without updating its expectation must not pass silently."""
    assert case.input_path.exists()
    assert case.actual_sha256() == case.declared_sha256


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_the_expectation_is_a_legal_evidence_record(case: GoldenCase) -> None:
    """Every committed expectation obeys the contract it will one day be compared against.

    `load_case` already constructs each record through `Evidence`, so a
    malformed golden fails at collection. This pins the parts the contract
    cannot: that the record names the detector the case is for, and that it
    refers to the fixture actually committed beside it.
    """
    assert case.expected
    for item in case.expected:
        assert isinstance(item, Evidence)
        assert item.detector_id == case.detector_id
        assert item.input_digest == case.actual_sha256()


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_authoritative_expectations_cite_a_standard(case: GoldenCase) -> None:
    """Rung 0 and Rung 1 decide cases, so their goldens must name the rule applied."""
    for item in case.expected:
        if item.rung in (Rung.CRYPTOGRAPHIC, Rung.DETERMINISTIC):
            assert item.standard_ref


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_no_expectation_puts_jargon_in_front_of_an_officer(case: GoldenCase) -> None:
    """`reasons` is read by someone who has never heard of a check digit.

    Committing the wording in a golden is what stops it drifting back into
    engineer-speak later, so the ban is enforced here rather than in review.
    """
    for item in case.expected:
        for reason in item.reasons:
            lowered = reason.lower()
            found = [word for word in JARGON if word in lowered]
            assert not found, f"{case.case_id} reason contains jargon {found}: {reason!r}"


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_no_expectation_claims_more_than_its_rung_allows(case: GoldenCase) -> None:
    """A golden must not be the place a detector quietly gains authority."""
    for item in case.expected:
        if item.rung is Rung.INFERENCE:
            assert item.result is not Result.PASS
        assert item.result is not Result.PROOF_VALID or item.rung is Rung.CRYPTOGRAPHIC


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_the_detector_reproduces_the_golden(case: GoldenCase) -> None:
    """Run the named detector against the fixture and require an exact match.

    Pending until the detector exists. This test needs no edit when it does:
    registering the detector is what switches it on.
    """
    builder = BUILDERS.get(case.detector_id)
    if builder is None:
        pytest.skip(f"{case.detector_id} is not implemented yet (phase {case.phase})")

    detector = builder(case.trust_store())
    subject = case.subject()
    actual = detector.run(subject) if detector.applies_to(subject) else ()

    assert_matches(actual, case.expected, case_id=case.case_id)


# ---------------------------------------------------------------------------
# Standards vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["mrz_check_digits.json", "verhoeff.json"])
def test_every_vector_file_is_licensed_and_traceable(name: str) -> None:
    """Vectors are fixtures too, and carry the same obligations."""
    vectors = load_vectors(name)

    assert vectors["licence"].strip()
    assert vectors["provenance"].strip()
    assert vectors["standard_ref"].strip()


def test_the_check_digit_vectors_are_well_formed() -> None:
    """Each vector is a field and the single digit it must produce."""
    vectors = load_vectors("mrz_check_digits.json")["vectors"]

    assert len(vectors) >= 10
    for vector in vectors:
        assert vector["field"]
        assert vector["check_digit"] in "0123456789"
        assert len(vector["check_digit"]) == 1
        assert vector["note"].strip()


def test_the_verhoeff_vectors_are_disjoint_and_non_empty() -> None:
    """A number cannot be in both lists, and neither list may be empty."""
    vectors = load_vectors("verhoeff.json")
    valid = set(vectors["valid"])
    invalid = set(vectors["invalid"])

    assert valid
    assert invalid
    assert not valid & invalid


def test_no_verhoeff_vector_could_be_a_real_aadhaar_number() -> None:
    """UIDAI never issues a number beginning with 0 or 1.

    The twelve-digit vectors deliberately begin with 0, so they exercise the
    arithmetic without any of them being a number that could belong to a real
    person. Rule 3 of CLAUDE.md is about storage, but a fixture corpus is
    storage.
    """
    vectors = load_vectors("verhoeff.json")

    for number in [*vectors["valid"], *vectors["invalid"]]:
        if len(number) == 12:
            assert number[0] == "0", f"{number} has the shape of an issuable Aadhaar number"
