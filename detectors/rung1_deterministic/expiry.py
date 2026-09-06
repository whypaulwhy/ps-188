"""Rung 1 detector: is the document still valid on the day it is presented?

Expiry is the one date check the machine-readable strip actually supports, and
this module is named for what it does rather than for what a broader date
detector might one day do.

**An expired document fails, and failing rejects.** That is a decision with a
cost, taken deliberately: `docs/threat-model.md` records that the people
crossing here are largely daily commuters, so a card that expired last month
turns the same person back every morning until they renew it. It is taken
because an expired travel document is not valid for travel, the date is not
arguable, and the officer is shown exactly which date failed and can override.
The alternative — treating expiry as advisory — would let a document that
expired twenty years ago clear on its signature alone.

**Why there is no date-of-birth plausibility check here.** There cannot
usefully be one. A strip codes a year with two digits, and
`core.standards.date_rules` resolves it into the hundred years ending on the
day of the crossing. Every resolution is therefore already a plausible living
age by construction, so a plausibility test would pass unconditionally and
mean nothing. A date of birth that can only be read as being in the future
fails to resolve at all, and is reported as unreadable rather than as false.

**The judgement is made against the capture time, not against now.** A case
replayed from the ledger in five years reaches the same verdict it reached at
the barrier.
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import DocumentType, Evidence, Result, Rung, Subject, ZoneName
from core.standards.date_rules import DateKind, interpret_yymmdd, is_expired
from core.standards.errors import DateFormatError, MrzFormatError
from core.standards.mrz.parse import parse_mrz
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "expiry/1.0.0"
STANDARD_REF: Final[str] = "ICAO Doc 9303 Part 3 s.4.2.2, date of expiry"

DOCUMENT_NAMES: Final[dict[DocumentType, str]] = {
    DocumentType.NEPALI_CITIZENSHIP_CERTIFICATE: "A Nepali citizenship certificate",
    DocumentType.BHUTANESE_CID: "A Bhutanese citizenship identity card",
}

UNREADABLE: Final[str] = (
    "The machine-readable strip could not be read in full, so the expiry date was "
    "not checked. This is a problem with the scan, not a sign that the document is false."
)
UNREADABLE_DATE: Final[str] = (
    "The expiry date on this document could not be read, so it was not checked."
)


@register
class ExpiryDetector(Detector):
    """Reads the expiry date from the strip and judges it against the capture time."""

    id = "rung1.expiry"
    rung = Rung.DETERMINISTIC

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Args:
            subject: The material under examination.

        Returns:
            Always true. A document with no strip is reported as not checked
            rather than silently skipped, so the officer can tell the
            difference between a date that passed and a date nobody read.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Check whether the document has expired.

        Args:
            subject: The material under examination.

        Returns:
            One piece of evidence. Never raises.
        """
        started = time.perf_counter()
        result, reasons = self._examine(subject)
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                reasons=reasons,
                standard_ref=STANDARD_REF,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )

    def _examine(self, subject: Subject) -> tuple[Result, tuple[str, ...]]:
        """Decide the result and the officer-facing reasons for one document."""
        zone = subject.zone(ZoneName.MRZ)
        if zone is None:
            name = DOCUMENT_NAMES.get(subject.declared_type, "This document")
            return Result.NOT_APPLICABLE, (
                f"{name} carries no machine-readable expiry date, so this check does "
                f"not apply to it. Nothing about this document was confirmed by this check.",
            )

        if not zone.complete:
            return Result.NOT_APPLICABLE, (UNREADABLE,)

        try:
            document = parse_mrz(zone.lines)
        except MrzFormatError:
            return Result.NOT_APPLICABLE, (UNREADABLE,)

        crossing = subject.provenance.captured_at.date()
        try:
            expiry = interpret_yymmdd(document.date_of_expiry, kind=DateKind.EXPIRY, today=crossing)
        except DateFormatError:
            return Result.NOT_APPLICABLE, (UNREADABLE_DATE,)

        shown = expiry.value.strftime("%d %B %Y")
        if is_expired(expiry.value, on=crossing):
            return Result.FAIL, (
                f"This document expired on {shown} and is no longer valid for travel.",
            )
        return Result.PASS, (f"This document is valid until {shown}.",)


def build() -> Detector:
    """Construct the expiry detector.

    Returns:
        The detector. The date it judges against comes from the subject's own
        capture time, so nothing needs passing in.
    """
    return ExpiryDetector()
