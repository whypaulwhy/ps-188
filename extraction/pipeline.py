"""Turning a capture into a `Subject` the detectors can be handed.

This is the seam ADR 0004 described: everything messy happens on this side of
it, and detectors receive a settled set of facts on the other. Lenses, glare,
skew, OCR and barcode decoding all fail in ways that are nobody's fault, and
every one of those failures is recorded rather than hidden.

Two rules run through it.

**Nothing is invented.** A zone that could not be read is marked incomplete
with empty lines, never filled with a best guess. A strip that was not found
produces no zone at all. The Rung 1 detectors already distinguish those two —
"this document has no strip" and "the strip could not be read" are different
sentences and lead to different conversations at the barrier.

**Everything not done is said.** Each failure adds a plain sentence to
`Subject.not_extracted`, which reaches the officer. Silence about a missing
check is a defect, not a clean result.
"""

from __future__ import annotations

import hashlib
from typing import Final

from core.contracts import (
    DOCUMENT_ROLE,
    LIVE_CAPTURE_ROLE,
    Artefact,
    DecodedCode,
    DocumentType,
    Provenance,
    Subject,
    TextZone,
    ZoneName,
)
from extraction.mrz_locate import locate_mrz
from extraction.ocr_adapter import read_mrz, read_printed_text
from extraction.preprocess import decode, normalise
from extraction.qr_decode import decode_qr

UNREADABLE_IMAGE: Final[str] = (
    "The captured file could not be opened as an image, so nothing on it was read."
)
NO_STRIP_FOUND: Final[str] = (
    "No machine-readable strip was found on this document. Many documents do not have one."
)


def build_subject(
    captured: bytes,
    *,
    provenance: Provenance,
    declared_type: DocumentType = DocumentType.UNRECOGNISED,
    live_captures: tuple[tuple[bytes, str], ...] = (),
) -> Subject:
    """Extract everything obtainable from one capture.

    Args:
        captured: The image exactly as received. Its digest is what detectors
            record, so it is never normalised before hashing.
        provenance: Where it came from and when it was captured.
        declared_type: What the document claims to be, when that is known.
        live_captures: Photographs of the person presenting the document, each
            with its media type, in the order they were taken. They travel
            after the document for the face checks. Nothing is read from them:
            a code or a strip in a photograph of a person is not the document's.

    Returns:
        The subject. Never raises: a capture that cannot be opened at all comes
        back with no zones and a stated reason.
    """
    document = Artefact(
        role=DOCUMENT_ROLE,
        media_type=provenance.media_type,
        sha256=hashlib.sha256(captured).hexdigest(),
        data=captured,
    )
    people = tuple(
        Artefact(
            role=LIVE_CAPTURE_ROLE,
            media_type=media_type,
            sha256=hashlib.sha256(photograph).hexdigest(),
            data=photograph,
        )
        for photograph, media_type in live_captures
    )

    try:
        image = decode(captured)
    except ValueError:
        return Subject(
            provenance=provenance,
            declared_type=declared_type,
            artefacts=(document, *people),
            not_extracted=(UNREADABLE_IMAGE,),
        )

    levelled = normalise(image)
    zones: list[TextZone] = []
    codes: list[DecodedCode] = []
    not_extracted: list[str] = []

    region = locate_mrz(levelled)
    if region is None:
        not_extracted.append(NO_STRIP_FOUND)
    else:
        reading = read_mrz(region.crop(levelled))
        zones.append(TextZone(name=ZoneName.MRZ, lines=reading.lines, complete=reading.complete))
        if reading.reason is not None:
            not_extracted.append(reading.reason)

    printed = read_printed_text(image)
    if printed.lines:
        zones.append(
            TextZone(
                name=ZoneName.VISUAL_INSPECTION,
                lines=printed.lines,
                complete=printed.complete,
            )
        )
    if printed.reason is not None:
        not_extracted.append(printed.reason)

    payloads, code_reason = decode_qr(image)
    codes.extend(DecodedCode(symbology="QR", payload=payload) for payload in payloads)
    if code_reason is not None:
        not_extracted.append(code_reason)

    return Subject(
        provenance=provenance,
        declared_type=declared_type,
        artefacts=(document, *people),
        zones=tuple(zones),
        codes=tuple(codes),
        not_extracted=tuple(not_extracted),
    )
