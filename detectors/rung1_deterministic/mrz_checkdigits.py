"""Rung 1 detector: recompute every ICAO 9303 check digit and compare with the printed one.

The machine-readable strip carries verification numbers over its own fields. A
field altered in place stops agreeing with the number beside it, which is what
this detector looks for. It catches a competent edit to a genuine document. It
catches nothing about a wholly fabricated one, because the arithmetic is
public and a forger computes it correctly — which is why this is Rung 1
evidence about internal consistency and never proof of anything.

**Three outcomes, and the difference between two of them decides whether a
traveller is turned back.**

* Every number agrees -> ``PASS``. Not a clearance: only Rung 0 clears.
* A number disagrees -> ``FAIL``, which rejects.
* The strip could not be read, or the document has none -> ``NOT_APPLICABLE``.

A strip that OCR could not capture in full is *not* a failed check. Treating a
malformed strip as a standards violation would reject travellers for the
quality of the scanner, which `docs/threat-model.md` counts as a first-order
harm on a border people cross daily.

**This detector applies to every document**, including those that cannot
possibly carry a strip. That is deliberate. If it declined to apply, a Nepali
citizenship certificate would produce no evidence at all about its strip, and
the officer would have no way to tell a check that passed from one that never
ran. Reporting ``NOT_APPLICABLE`` out loud is what the honesty rule in
CLAUDE.md requires.
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import DocumentType, Evidence, Result, Rung, Subject, ZoneName
from core.standards.errors import MrzFormatError
from core.standards.mrz.parse import COMPOSITE, parse_mrz, verify_check_digits
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "mrz_checkdigits/1.0.0"
STANDARD_REF: Final[str] = "ICAO Doc 9303 Part 3 s.4.2.2"

FIELD_NAMES: Final[dict[str, str]] = {
    "document_number": "document number",
    "date_of_birth": "date of birth",
    "date_of_expiry": "expiry date",
    "optional_data": "personal number",
}
"""What each protected field is called in front of an officer. No jargon."""

DOCUMENT_NAMES: Final[dict[DocumentType, str]] = {
    DocumentType.NEPALI_CITIZENSHIP_CERTIFICATE: "A Nepali citizenship certificate",
    DocumentType.BHUTANESE_CID: "A Bhutanese citizenship identity card",
}
"""How a document with no strip is named. Anything else is described generically."""

PASSED: Final[str] = (
    "The machine-readable strip at the bottom of this passport is self-consistent: "
    "every built-in verification number matches the details printed beside it."
)
COMPOSITE_ALSO_FAILED: Final[str] = (
    "The strip's overall verification number does not match either, which is what a "
    "single altered field normally looks like."
)
COMPOSITE_ONLY_FAILED: Final[str] = (
    "The strip's overall verification number does not match the rest of the strip, "
    "although each field on its own does."
)
UNREADABLE: Final[str] = (
    "The machine-readable strip could not be read in full, so it was not checked. "
    "This is a problem with the scan, not a sign that the document is false."
)


@register
class MrzCheckDigitsDetector(Detector):
    """Recomputes the machine-readable strip's own verification numbers."""

    id = "rung1.mrz_checkdigits"
    rung = Rung.DETERMINISTIC

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Args:
            subject: The material under examination.

        Returns:
            Always true. A document with no strip is reported as not checked
            rather than silently skipped; see the module docstring.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Check every verification number on the strip.

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
                f"{name} has no machine-readable strip, so this check does not "
                f"apply to it. Nothing about this document was confirmed by this check.",
            )

        if not zone.complete:
            return Result.NOT_APPLICABLE, (UNREADABLE,)

        try:
            document = parse_mrz(zone.lines)
        except MrzFormatError:
            return Result.NOT_APPLICABLE, (UNREADABLE,)

        results = verify_check_digits(document)
        failed = [item for item in results if not item.matches]
        if not failed:
            return Result.PASS, (PASSED,)

        reasons = [
            f"The {FIELD_NAMES[item.name]} in the machine-readable strip does not "
            f"match the verification number printed next to it."
            for item in failed
            if item.name != COMPOSITE
        ]
        if any(item.name == COMPOSITE for item in failed):
            reasons.append(COMPOSITE_ALSO_FAILED if reasons else COMPOSITE_ONLY_FAILED)
        return Result.FAIL, tuple(reasons)


def build() -> Detector:
    """Construct the MRZ check-digit detector.

    Returns:
        The detector. It needs nothing passed in: the strip carries everything
        the check requires.
    """
    return MrzCheckDigitsDetector()
