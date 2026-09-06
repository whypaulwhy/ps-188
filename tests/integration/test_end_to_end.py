"""A photograph in, a verdict out.

This is the path nothing before phase 6 could demonstrate: a captured image
flows through extraction into a `Subject`, through the detectors written in
phases 4 and 5, and out as a decision an officer reads.

The assertions are deliberately about **behaviour that must hold whatever is
installed**. Whether the strip can be read here depends on a reader this
machine may or may not have, so the tests below assert the honest-degradation
contract rather than a particular outcome: nothing crashes, nothing is
invented, and anything not done is said out loud.
"""

from __future__ import annotations

import datetime
import hashlib

from core.contracts import Decision, DocumentType, Provenance, Result, ZoneName
from core.trust import resolve
from datagen.forgeries.photo_substitution import PhotoSubstitution
from datagen.synthetic_docs import generate_specimen
from detectors.rung1_deterministic import expiry, mrz_checkdigits
from extraction.pipeline import build_subject

WHEN = datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.UTC)
SPECIMEN = generate_specimen(seed=1)


def screen(captured: bytes, label: str = "case"):  # noqa: ANN201
    """Run one capture through extraction, the detectors, and the ladder."""
    record = Provenance(
        source_id=label,
        sha256=hashlib.sha256(captured).hexdigest(),
        media_type="image/png",
        byte_size=len(captured),
        captured_at=WHEN,
        received_at=WHEN,
        checkpoint_id="integration",
    )
    subject = build_subject(captured, provenance=record, declared_type=DocumentType.UNRECOGNISED)
    evidence = [
        item
        for detector in (mrz_checkdigits.build(), expiry.build())
        if detector.applies_to(subject)
        for item in detector.run(subject)
    ]
    return subject, resolve(evidence, provenance=record, decided_at=WHEN)


def test_a_photograph_produces_a_verdict() -> None:
    """The end-to-end path, closed for the first time in this phase."""
    subject, verdict = screen(SPECIMEN.png)

    assert subject.artefacts[0].sha256 == hashlib.sha256(SPECIMEN.png).hexdigest()
    assert verdict.decision in set(Decision)
    assert verdict.basis


def test_the_strip_is_found_on_a_real_capture() -> None:
    """Extraction locates the strip even when it cannot read it."""
    subject, _ = screen(SPECIMEN.png)

    assert subject.zone(ZoneName.MRZ) is not None


def test_the_printed_page_is_read() -> None:
    """The general recogniser is used where it is reliable, and it is here."""
    subject, _ = screen(SPECIMEN.png)

    zone = subject.zone(ZoneName.VISUAL_INSPECTION)

    assert zone is not None
    assert any("SPECIMEN" in line.upper() for line in zone.lines)


def test_nothing_is_ever_cleared_by_this_path() -> None:
    """No detector in this pipeline is Rung 0, so nothing here can clear a document.

    Stated as a test because it is the property the whole ladder exists to
    guarantee, and because an image pipeline is exactly where someone would be
    tempted to let a clean read imply a clean document.
    """
    for captured in (SPECIMEN.png, PhotoSubstitution().apply(SPECIMEN, seed=2)):
        _subject, verdict = screen(captured)

        assert verdict.decision is not Decision.CLEARED


def test_a_capture_that_is_not_an_image_still_produces_a_verdict() -> None:
    """Garbage in must not crash a checkpoint. It must produce an honest answer."""
    subject, verdict = screen(b"not an image at all", label="corrupt")

    assert subject.zones == ()
    assert subject.not_extracted
    assert verdict.decision is Decision.MANUAL_REVIEW


def test_whatever_was_not_extracted_reaches_the_officer() -> None:
    """The honesty rule, checked at the seam where things actually go unread."""
    subject, verdict = screen(SPECIMEN.png)

    if subject.not_extracted:
        assert all(sentence.strip().endswith(".") for sentence in subject.not_extracted)
    if any(item.result is Result.NOT_APPLICABLE for item in verdict.evidence):
        assert verdict.not_checked


def test_a_strip_that_was_not_read_is_never_treated_as_one_that_passed() -> None:
    """The contract, whatever reader is installed on this machine.

    A strip the reader could not vouch for must reach the officer as a check
    that did not happen, with a stated reason — never as a silent pass and
    never as a failure the traveller is turned back on.
    """
    subject, verdict = screen(SPECIMEN.png)
    zone = subject.zone(ZoneName.MRZ)
    assert zone is not None

    if not zone.complete:
        assert zone.lines == ()
        assert subject.not_extracted
        assert verdict.decision is Decision.MANUAL_REVIEW
        assert all(item.result is Result.NOT_APPLICABLE for item in verdict.evidence)
        assert verdict.not_checked
    else:
        assert all(len(line) == 44 for line in zone.lines)
        assert verdict.decision is not Decision.CLEARED


def test_a_reader_is_installed_or_the_case_says_so() -> None:
    """Whichever is true, the officer is told. Silence is the one unacceptable state."""
    subject, _ = screen(SPECIMEN.png)
    zone = subject.zone(ZoneName.MRZ)
    assert zone is not None

    assert zone.complete or any("could not be read" in line for line in subject.not_extracted)
