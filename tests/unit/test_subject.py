"""The extraction contract: what a detector is handed.

The contract is small on purpose — there are no real captures to design it
against yet. What these tests pin is the part that will not change: a zone that
was not recovered is absent rather than empty, so "we found nothing wrong" can
never be confused with "we could not look".
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.contracts import Artefact, DecodedCode, DocumentType, Subject, TextZone, ZoneName
from tests.support import DIGEST, provenance, subject


def test_a_subject_defaults_to_an_unrecognised_document() -> None:
    """Recognition is something extraction establishes, never something assumed."""
    bare = Subject(provenance=provenance())

    assert bare.declared_type is DocumentType.UNRECOGNISED
    assert bare.zones == ()
    assert bare.codes == ()
    assert bare.not_extracted == ()


def test_a_missing_zone_is_absent_rather_than_empty() -> None:
    """The distinction the NOT_APPLICABLE golden cases rest on."""
    document = subject()

    assert document.zone(ZoneName.MRZ) is not None
    assert document.zone(ZoneName.PORTRAIT) is None


def test_an_unreadable_zone_is_marked_incomplete() -> None:
    """A partially captured strip is a check that cannot be made, not one that failed."""
    document = subject(zones=(TextZone(name=ZoneName.MRZ, lines=("SHORT",), complete=False),))

    zone = document.zone(ZoneName.MRZ)

    assert zone is not None
    assert not zone.complete


def test_a_subject_cannot_hold_two_readings_of_one_zone() -> None:
    """Two readings would make lookup arbitrary, and the arbitrary one might be the clean one."""
    with pytest.raises(ValidationError, match="at most one reading"):
        subject(
            zones=(
                TextZone(name=ZoneName.MRZ, lines=("A",), complete=True),
                TextZone(name=ZoneName.MRZ, lines=("B",), complete=True),
            )
        )


def test_zone_lines_cannot_contain_line_breaks() -> None:
    """Line indices are meaningful in a strip, so a smuggled newline is rejected."""
    with pytest.raises(ValidationError, match="line break"):
        TextZone(name=ZoneName.MRZ, lines=("first\nsecond",), complete=True)


def test_artefacts_are_looked_up_by_role() -> None:
    """A case can carry several captures; a detector asks for the one it needs."""
    document = subject()

    front = document.artefact("document_front")

    assert front is not None
    assert front.media_type == "text/plain"
    assert document.artefact("live_capture") is None


def test_a_decoded_code_keeps_its_bytes_exactly() -> None:
    """Signature verification depends on the payload byte for byte."""
    payload = b"\x00\x01\xff not text"
    code = DecodedCode(symbology="QR", payload=payload, zone=ZoneName.VISUAL_INSPECTION)

    assert code.payload == payload


def test_a_subject_is_frozen() -> None:
    """A detector reads a subject; it never edits one."""
    document = subject()

    with pytest.raises(ValidationError):
        document.declared_type = DocumentType.AADHAAR  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    """A typo in a field name fails loudly rather than being dropped."""
    with pytest.raises(ValidationError):
        Subject(provenance=provenance(), document_type=DocumentType.AADHAAR)


def test_not_extracted_carries_plain_sentences_for_the_officer() -> None:
    """The same honesty rule as Verdict.not_checked, one layer down."""
    document = subject(
        not_extracted=("The code on the back of the card could not be read.",),
    )

    assert document.not_extracted == ("The code on the back of the card could not be read.",)


def test_an_artefact_records_the_digest_a_detector_will_report() -> None:
    """Evidence.input_digest has to name the exact bytes examined."""
    artefact = Artefact(
        role="document_front", media_type="image/jpeg", sha256=DIGEST, data=b"jpeg bytes"
    )

    assert artefact.sha256 == DIGEST


def test_every_accepted_document_type_in_scope_has_a_member() -> None:
    """The enum is a scope decision, so it tracks docs/scope.md rather than drifting.

    Ten distinct accepted types plus UNRECOGNISED. The scope table has eleven
    rows because Aadhaar appears twice, once with a readable Secure QR and once
    without; those are the same document captured differently. Adding a member
    here means accepting a document type for screening, which belongs in
    scope.md first.
    """
    assert len(DocumentType) == 11
    assert DocumentType.UNRECOGNISED in DocumentType
