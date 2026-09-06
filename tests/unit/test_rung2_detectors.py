"""The Rung 2 detectors, tested for contract compliance and nothing else.

CLAUDE.md is explicit: a Rung 2 detector is never accuracy-tested here. Accuracy
comes from `eval/run_eval.py` on a named dataset, and a unit test asserting a
detection rate would be a fabricated metric wearing a test's clothes.

What is tested is the contract: the right shape, no exception on malformed
input, and `INCONCLUSIVE` when the model is unavailable. Plus the property the
whole ladder rests on — that none of these can clear a document.
"""

from __future__ import annotations

import datetime
import hashlib

import pytest

from core.contracts import Artefact, Evidence, Provenance, Result, Rung, Subject
from datagen.synthetic_docs import generate_specimen
from detectors.rung2_inference import (
    metadata_forensics,
    pdf_structure,
    tamper_classical,
    tamper_trufor,
)

IMAGE_DETECTORS = [tamper_classical, metadata_forensics, tamper_trufor]
ALL_DETECTORS = [*IMAGE_DETECTORS, pdf_structure]

WHEN = datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.UTC)
SPECIMEN = generate_specimen(seed=1)


def subject(data: bytes, media_type: str = "image/png") -> Subject:
    """Build a subject carrying one artefact."""
    digest = hashlib.sha256(data).hexdigest()
    return Subject(
        provenance=Provenance(
            source_id="case",
            sha256=digest,
            media_type=media_type,
            byte_size=len(data),
            captured_at=WHEN,
            received_at=WHEN,
            checkpoint_id="unit",
        ),
        artefacts=(
            Artefact(role="document_front", media_type=media_type, sha256=digest, data=data),
        ),
    )


@pytest.mark.parametrize("module", ALL_DETECTORS, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_a_rung2_detector_declares_rung_two(module: object) -> None:
    """The declaration is what fixes what it is allowed to say."""
    assert module.build().rung is Rung.INFERENCE  # type: ignore[attr-defined]


@pytest.mark.parametrize("module", IMAGE_DETECTORS, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_the_shape_of_the_output_is_correct(module: object) -> None:
    """One piece of evidence, naming the bytes it examined."""
    document = subject(SPECIMEN.png)

    evidence = module.build().run(document)  # type: ignore[attr-defined]

    assert len(evidence) == 1
    assert isinstance(evidence[0], Evidence)
    assert evidence[0].input_digest == document.artefacts[0].sha256


@pytest.mark.parametrize("module", IMAGE_DETECTORS, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_malformed_input_does_not_raise(module: object) -> None:
    """A detector that crashes is indistinguishable from one that found nothing wrong."""
    (evidence,) = module.build().run(subject(b"not an image at all"))  # type: ignore[attr-defined]

    assert evidence.result in {Result.INCONCLUSIVE, Result.NO_FINDING, Result.SUSPICIOUS}


@pytest.mark.parametrize("module", IMAGE_DETECTORS, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_no_rung2_detector_can_clear_a_document(module: object) -> None:
    """The property the whole trust ladder rests on.

    A Rung 2 detector has no vocabulary for asserting authenticity. This is
    enforced by the evidence contract, and asserted here at the point of
    production because it is the single most important property in the system.
    """
    for data in (SPECIMEN.png, b"garbage"):
        for evidence in module.build().run(subject(data)):  # type: ignore[attr-defined]
            assert evidence.result is not Result.PROOF_VALID
            assert evidence.result is not Result.PASS
            assert evidence.result in {
                Result.NO_FINDING,
                Result.SUSPICIOUS,
                Result.INCONCLUSIVE,
            }


@pytest.mark.parametrize("module", IMAGE_DETECTORS, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_a_score_is_suspicion_within_range(module: object) -> None:
    """Score is suspicion in [0, 1], so a larger number can only make a case worse."""
    for evidence in module.build().run(subject(SPECIMEN.png)):  # type: ignore[attr-defined]
        if evidence.score is not None:
            assert 0.0 <= evidence.score <= 1.0
            assert evidence.uncertainty is not None


# ---------------------------------------------------------------------------
# The unavailable model
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    tamper_trufor.weights_path() is not None,
    reason="TruFor weights are configured on this machine",
)
def test_trufor_is_inconclusive_when_its_model_is_absent() -> None:
    """The behaviour CLAUDE.md's testing rule asks for, and this deployment's state.

    No weights are available, so this detector abstains on every document and
    says so in words the officer reads. It is not silently reporting a clean
    result.
    """
    (evidence,) = tamper_trufor.build().run(subject(SPECIMEN.png))

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.score is None
    assert "not installed" in evidence.reasons[0]


@pytest.mark.skipif(
    tamper_trufor.weights_path() is not None,
    reason="TruFor weights are configured on this machine",
)
def test_trufor_reports_its_model_version_as_unavailable() -> None:
    """The audit record has to show which model produced a result, including none."""
    (evidence,) = tamper_trufor.build().run(subject(SPECIMEN.png))

    assert "unavailable" in evidence.model_version


def test_absent_metadata_is_not_treated_as_suspicious() -> None:
    """The trap this detector is written around.

    Scans and screenshots routinely carry no metadata. Treating its absence as
    a signal would escalate most genuine documents at these crossings, so the
    honest answer is that the check did not happen.
    """
    (evidence,) = metadata_forensics.build().run(subject(SPECIMEN.png))

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.score is None


# ---------------------------------------------------------------------------
# Applicability
# ---------------------------------------------------------------------------


def test_the_pdf_detector_ignores_images() -> None:
    """A detector that does not apply produces nothing rather than a guess."""
    assert not pdf_structure.build().applies_to(subject(SPECIMEN.png))


def test_the_image_detectors_ignore_pdfs() -> None:
    """And the reverse."""
    document = subject(b"%PDF-1.7 not really", media_type="application/pdf")

    for module in IMAGE_DETECTORS:
        assert not module.build().applies_to(document)  # type: ignore[attr-defined]


def test_an_unreadable_pdf_is_inconclusive_rather_than_suspicious() -> None:
    """Failing to parse a file says nothing about whether it was altered."""
    (evidence,) = pdf_structure.build().run(
        subject(b"%PDF-1.7 not really a pdf", media_type="application/pdf")
    )

    assert evidence.result is Result.INCONCLUSIVE
