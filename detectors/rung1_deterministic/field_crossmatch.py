"""Rung 1 detector: does the coded strip agree with the printed page?

The forgery this answers is the one a check-digit test cannot see. Alter a
printed field and leave the strip alone, and the strip stays perfectly
self-consistent — every verification number still matches, because none of them
covers the ink on the front of the document. Only a comparison between the two
notices.

**This detector is written to be reluctant, because a Rung 1 failure rejects.**
Printed text is recovered by a general text recogniser, which makes mistakes.
A mismatch caused by a misread letter would turn a real traveller back. So:

* it runs only when **both** zones are marked complete by extraction. If either
  the strip or the printed page was not fully recovered, this reports
  `NOT_APPLICABLE` rather than comparing a partial reading;
* it compares only the **surname**, which is the longest and most distinctive
  field and the one a recogniser is least likely to mangle beyond recognition;
* it compares letters only, ignoring spacing, case and punctuation, because
  those differ between the strip and the printed page by design.

It does **not** invent a field structure for the printed page. There is no
parsing of labels into values here — that needs a real capture to design
against, and `Subject` carries the printed page as lines of text. What it asks
is narrower and answerable: does the name coded in the strip appear anywhere on
the front of the document?
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject, ZoneName
from core.standards.errors import MrzFormatError
from core.standards.mrz.parse import parse_mrz
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "field_crossmatch/1.0.0"
STANDARD_REF: Final[str] = "ICAO Doc 9303 Part 3 s.4.2, visual inspection zone consistency"

MINIMUM_SURNAME: Final[int] = 4
"""Shorter than this and a chance match in the printed text proves nothing."""

NOT_BOTH_READ: Final[str] = (
    "The coded strip and the printed page could not both be read in full, so they "
    "were not compared. This is a problem with the scan, not a sign that the "
    "document is false."
)
NO_STRIP: Final[str] = (
    "This document has no coded strip to compare against what is printed on it, so "
    "this check does not apply. Nothing about this document was confirmed by it."
)
TOO_SHORT: Final[str] = (
    "The name in the coded strip is too short to look for reliably on the printed "
    "page, so the two were not compared."
)


def _letters(value: str) -> str:
    """Reduce text to bare uppercase letters, so spacing and punctuation cannot differ."""
    return "".join(character for character in value.upper() if character.isalpha())


@register
class FieldCrossmatchDetector(Detector):
    """Checks the name coded in the strip against the printed page."""

    id = "rung1.field_crossmatch"
    rung = Rung.DETERMINISTIC

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        A document with no strip is reported as not checked rather than
        silently skipped, so the officer can tell the difference between a
        comparison that passed and one that never happened.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Compare the coded name against the printed page."""
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
        strip = subject.zone(ZoneName.MRZ)
        printed = subject.zone(ZoneName.VISUAL_INSPECTION)

        if strip is None:
            return Result.NOT_APPLICABLE, (NO_STRIP,)
        if printed is None or not strip.complete or not printed.complete:
            return Result.NOT_APPLICABLE, (NOT_BOTH_READ,)

        try:
            document = parse_mrz(strip.lines)
        except MrzFormatError:
            return Result.NOT_APPLICABLE, (NOT_BOTH_READ,)

        surname = _letters(document.surname)
        if len(surname) < MINIMUM_SURNAME:
            return Result.NOT_APPLICABLE, (TOO_SHORT,)

        page = _letters(" ".join(printed.lines))
        if surname in page:
            return Result.PASS, (
                "The name in the coded strip matches the name printed on the document.",
            )
        return Result.FAIL, (
            "The name in the coded strip does not appear anywhere on the printed "
            "front of this document. On a genuine document the two always agree.",
        )


def build() -> Detector:
    """Construct the strip-versus-printed-page cross-consistency detector."""
    return FieldCrossmatchDetector()
