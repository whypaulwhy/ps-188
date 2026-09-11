"""What a detector is handed: everything extraction managed to establish.

A `Subject` is the boundary between the messy half of the system and the clean
half. Extraction deals with lenses, glare, skew, OCR and barcode decoding, all
of which fail in ways that are nobody's fault. A detector deals with a settled
set of facts and reports evidence about them. Putting the boundary here means
detectors never touch a file, a camera or a model runtime, and never learn what
a decision will be used for.

**This contract lives in `core` on purpose.** If it lived in `extraction`, every
detector would import NumPy and OpenCV transitively and the purity rule in
`setup.cfg` would be unenforceable. So image bytes are carried opaquely: a
detector that needs pixels decodes them with its own libraries, and `core`
stays free of them.

**It is deliberately minimal.** The roadmap says this contract is designed
against real captures, and there are none yet — phase 1 committed data-level
fixtures only. What is here is what phases 4 and 5 actually need: decoded
codes, located text zones, the raw artefact bytes, and an honest record of what
extraction could not do. It is expected to grow in phase 6 when images first
flow through it, and growing it is not a redesign.

`not_extracted` is the same idea as `Verdict.not_checked`, one layer down. A
zone that could not be read is recorded, never omitted, so that "we found
nothing wrong" can always be distinguished from "we could not look".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.contracts.provenance import Provenance

DOCUMENT_ROLE: Final[str] = "document_front"
"""The artefact every check about the document reads, and the only one.

A check that chose its input as "the first image" or "the first PDF" could be
handed a photograph of the person, or a signed file that was never the document.
"""

LIVE_CAPTURE_ROLE: Final[str] = "live_capture"
"""A photograph of the person presenting the document, taken at the checkpoint."""


class DocumentType(StrEnum):
    """What a presented document claims to be.

    One entry per accepted type in `docs/scope.md`, plus `UNRECOGNISED`. The
    list is a scope decision, not a technical one: adding a member here means
    accepting a document type for screening, and that belongs in `scope.md`
    first.
    """

    AADHAAR = "AADHAAR"
    DIGILOCKER_DOCUMENT = "DIGILOCKER_DOCUMENT"
    INDIAN_PASSPORT = "INDIAN_PASSPORT"
    NEPALI_PASSPORT = "NEPALI_PASSPORT"
    BHUTANESE_PASSPORT = "BHUTANESE_PASSPORT"
    INDIAN_DRIVING_LICENCE = "INDIAN_DRIVING_LICENCE"
    EPIC_VOTER_CARD = "EPIC_VOTER_CARD"
    NEPALI_CITIZENSHIP_CERTIFICATE = "NEPALI_CITIZENSHIP_CERTIFICATE"
    NEPALI_NATIONAL_ID = "NEPALI_NATIONAL_ID"
    BHUTANESE_CID = "BHUTANESE_CID"

    UNRECOGNISED = "UNRECOGNISED"
    """Not a type this system screens. Detectors that need no template may still run."""


class ZoneName(StrEnum):
    """The named regions extraction tries to locate on a document."""

    MRZ = "MRZ"
    """The machine-readable strip."""

    VISUAL_INSPECTION = "VISUAL_INSPECTION"
    """The printed fields a person reads."""

    PORTRAIT = "PORTRAIT"
    """The bearer's photograph."""


class TextZone(BaseModel):
    """Text recovered from one named region of a document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: ZoneName
    """Which region this is."""

    lines: tuple[str, ...] = ()
    """The recovered lines, in reading order, exactly as read. Never repaired."""

    complete: bool
    """Whether the whole region was captured.

    False means part of it was cut off, obscured or unreadable. A detector must
    treat an incomplete zone as a check it could not make, not as a check that
    failed.
    """

    @field_validator("lines")
    @classmethod
    def _lines_have_no_line_breaks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject embedded newlines, which would make line indices meaningless."""
        for line in value:
            if "\n" in line or "\r" in line:
                msg = "a zone line must not contain a line break"
                raise ValueError(msg)
        return value


class DecodedCode(BaseModel):
    """One barcode or QR code decoded from a document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    symbology: Annotated[str, Field(min_length=1, max_length=32)]
    """How the code was encoded, for example `QR` or `PDF417`."""

    payload: bytes
    """The decoded bytes, unmodified. Signature verification depends on them exactly."""

    zone: ZoneName | None = None
    """Where on the document the code was found, when that is known."""


class Artefact(BaseModel):
    """One captured file, carried alongside what was extracted from it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Annotated[str, Field(min_length=1, max_length=64)]
    """What this is, for example `document_front` or `live_capture`."""

    media_type: Annotated[str, Field(min_length=3, max_length=128)]
    """IANA media type."""

    sha256: Annotated[str, Field(min_length=64, max_length=64)]
    """Digest of `data`. What a detector records as its `input_digest`."""

    data: bytes
    """The bytes themselves. Opaque to `core`; detectors decode them as needed."""


class Subject(BaseModel):
    """One presented document, as far as extraction could establish it.

    Immutable. A detector receives this, reads what it needs, and returns
    evidence. It does not modify the subject and cannot reach anything outside
    it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provenance: Provenance
    """Where the material came from and when it was captured."""

    declared_type: DocumentType = DocumentType.UNRECOGNISED
    """What the document claims to be. Never proof of what it is."""

    artefacts: tuple[Artefact, ...] = ()
    """The captured files."""

    zones: tuple[TextZone, ...] = ()
    """Text recovered from named regions."""

    codes: tuple[DecodedCode, ...] = ()
    """Barcodes and QR codes decoded from the document."""

    not_extracted: tuple[str, ...] = ()
    """What extraction could not do, in plain sentences.

    A QR code that would not decode, a strip that was cut off, a portrait that
    could not be located. These reach the officer, so a detector reporting
    `NOT_APPLICABLE` because a zone is missing has a reason to quote.
    """

    @field_validator("zones")
    @classmethod
    def _zones_are_distinct(cls, value: tuple[TextZone, ...]) -> tuple[TextZone, ...]:
        """Reject two readings of the same region, which would make lookup arbitrary."""
        names = [zone.name for zone in value]
        if len(names) != len(set(names)):
            msg = "a subject may hold at most one reading of each zone"
            raise ValueError(msg)
        return value

    def zone(self, name: ZoneName) -> TextZone | None:
        """Return the reading of one region, or None if it was not recovered.

        Args:
            name: The region to look up.

        Returns:
            The zone, or None. None means extraction did not recover it, which
            a detector must report as a check it could not make.
        """
        for zone in self.zones:
            if zone.name is name:
                return zone
        return None

    def artefact(self, role: str) -> Artefact | None:
        """Return the captured file with a given role, or None.

        Args:
            role: The role to look up, for example `document_front`.

        Returns:
            The first artefact with that role, or None.
        """
        for artefact in self.artefacts:
            if artefact.role == role:
                return artefact
        return None
