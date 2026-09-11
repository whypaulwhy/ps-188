"""Rung 2 detector: structural anomalies in a PDF, short of the signature check.

A PDF records its own edit history. Every time a file is changed after being
written, a new revision is appended rather than the original being rewritten, so
the number of revisions is a fact about the document rather than an inference
about its pixels.

**This is deliberately separate from the Rung 0 signature check.** Verifying a
signature answers whether the issuer signed these bytes. This answers a
different and weaker question — how many times has this file been written to? —
and it can only escalate. A document edited after signing is already caught at
Rung 0 with proof; this catches the case where there is no signature to check.

**Extra revisions are not evidence of forgery.** Adding a comment, filling a
form field or re-saving in a viewer all append a revision legitimately. That is
why this escalates for a person to look at and can never reject.
"""

from __future__ import annotations

import io
import time
from typing import Final

from core.contracts import DOCUMENT_ROLE, Artefact, Evidence, Result, Rung, Subject
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "pdf_structure/1.0.0"
PDF_MEDIA_TYPE: Final[str] = "application/pdf"

EXPECTED_REVISIONS: Final[int] = 2
"""A document written once and then signed has two. More means it was edited after."""

UNREADABLE: Final[str] = (
    "The internal structure of this document could not be read, so its history was not checked."
)


@register
class PdfStructureDetector(Detector):
    """Counts how many times a PDF has been written to since it was created."""

    id = "rung2.pdf_structure"
    rung = Rung.INFERENCE

    @staticmethod
    def _document(subject: Subject) -> Artefact | None:
        """Return the document if it is a PDF. No other artefact is examined here."""
        document = subject.artefact(DOCUMENT_ROLE)
        if document is None or document.media_type != PDF_MEDIA_TYPE:
            return None
        return document

    def applies_to(self, subject: Subject) -> bool:
        """Report whether the document is a PDF."""
        return self._document(subject) is not None

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Count revisions and report suspicion, never authenticity."""
        started = time.perf_counter()
        artefact = self._document(subject)
        if artefact is None:
            return ()

        try:
            from pyhanko.pdf_utils.reader import PdfFileReader

            revisions = int(PdfFileReader(io.BytesIO(artefact.data)).xrefs.total_revisions)
        except Exception:  # a failure to read is a result, not a crash
            return (
                self._evidence(Result.INCONCLUSIVE, (UNREADABLE,), None, None, artefact, started),
            )

        if revisions > EXPECTED_REVISIONS:
            extra = revisions - EXPECTED_REVISIONS
            return (
                self._evidence(
                    Result.SUSPICIOUS,
                    (
                        f"This document has been saved again {extra} time(s) since it "
                        f"was first written. That happens for ordinary reasons too, "
                        f"such as filling in a field or re-saving it.",
                        "This is not proof of anything on its own, and a person should look at it.",
                    ),
                    min(1.0, 0.4 + 0.2 * extra),
                    0.5,
                    artefact,
                    started,
                ),
            )

        return (
            self._evidence(
                Result.NO_FINDING,
                (
                    "This document does not appear to have been edited after it was "
                    "written. This is not proof that it is genuine.",
                ),
                0.0,
                0.5,
                artefact,
                started,
            ),
        )

    def _evidence(
        self,
        result: Result,
        reasons: tuple[str, ...],
        score: float | None,
        uncertainty: float | None,
        artefact: object,
        started: float,
    ) -> Evidence:
        """Assemble one piece of evidence from this detector."""
        return Evidence(
            detector_id=self.id,
            rung=self.rung,
            result=result,
            score=score,
            uncertainty=uncertainty,
            reasons=reasons,
            runtime_ms=(time.perf_counter() - started) * 1000,
            model_version=DETECTOR_VERSION,
            input_digest=artefact.sha256,  # type: ignore[attr-defined]
        )


def build() -> Detector:
    """Construct the PDF structural anomaly detector."""
    return PdfStructureDetector()
