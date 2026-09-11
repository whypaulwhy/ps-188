"""A check about the document reads the document, and nothing sent with it.

Six detectors choose their input by the kind of file it is: XML, PDF or image.
Before phase 19 a screening carried one file, so "the first PDF" and "the
document" were the same thing. Photographs of the person changed that. Each of
these checks now examines the artefact in the document's role and nothing else,
and the tests below pin it from both sides: a file of the right kind in another
role is not examined, and when the document is of that kind it is the document
that is examined, even with the other file listed first.
"""

from __future__ import annotations

from typing import Final

import pytest

from core.contracts import DOCUMENT_ROLE, LIVE_CAPTURE_ROLE, Artefact, Subject
from detectors.base import Detector
from detectors.rung0_crypto import digilocker_xml_sig, pdf_pkcs7
from detectors.rung0_crypto.trust_store import TrustStore
from detectors.rung2_inference import (
    metadata_forensics,
    pdf_structure,
    tamper_classical,
    tamper_trufor,
)
from tests.support import provenance

DOCUMENT_DIGEST: Final[str] = "d" * 64
OTHER_DIGEST: Final[str] = "e" * 64

CHECKS: Final[dict[str, tuple[Detector, str]]] = {
    "digilocker_xml_sig": (digilocker_xml_sig.build(TrustStore()), "application/xml"),
    "pdf_pkcs7": (pdf_pkcs7.build(TrustStore()), "application/pdf"),
    "pdf_structure": (pdf_structure.build(), "application/pdf"),
    "metadata_forensics": (metadata_forensics.build(), "image/jpeg"),
    "tamper_classical": (tamper_classical.build(), "image/jpeg"),
    "tamper_trufor": (tamper_trufor.build(), "image/jpeg"),
}
"""Each check that selects its input by kind of file, and a kind it examines."""


def carrying(*, document: str, other: str) -> Subject:
    """Return a subject whose other file is listed first, so order cannot decide."""
    return Subject(
        provenance=provenance(),
        artefacts=(
            Artefact(
                role=LIVE_CAPTURE_ROLE, media_type=other, sha256=OTHER_DIGEST, data=b"sent with it"
            ),
            Artefact(
                role=DOCUMENT_ROLE, media_type=document, sha256=DOCUMENT_DIGEST, data=b"document"
            ),
        ),
    )


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_a_file_sent_with_the_document_is_not_examined_as_the_document(name: str) -> None:
    """A signed PDF labelled as a photograph of the person must never be verified."""
    detector, kind = CHECKS[name]
    subject = carrying(document="text/plain", other=kind)

    assert detector.applies_to(subject) is False
    assert detector.run(subject) == ()


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_the_document_is_examined_when_it_is_of_that_kind(name: str) -> None:
    """The other half, so the test above cannot pass on a check that examines nothing."""
    detector, kind = CHECKS[name]
    subject = carrying(document=kind, other=kind)

    assert detector.applies_to(subject) is True
    evidence = detector.run(subject)
    assert evidence
    assert {item.input_digest for item in evidence} == {DOCUMENT_DIGEST}
