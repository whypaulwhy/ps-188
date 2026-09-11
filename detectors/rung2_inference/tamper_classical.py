"""Rung 2 detector: classical tamper signals.

Error level analysis, noise localisation and duplicated-block detection. No
learned model: these are arithmetic over pixels, which is why they can ship
before any weights exist.

**This detector can only escalate.** Its vocabulary has no way to say a document
is genuine — `NO_FINDING` means it looked and raised nothing, which is a
different statement and is inert to the trust ladder. `score` is *suspicion*, so
a larger number can only ever make a case worse.

**What it actually detects, measured rather than assumed.** Three signals are
computed. On the evaluation dataset only one separates anything, and it
separates exactly one forgery type:

| signal | genuine | recapture | every other forgery |
|---|---|---|---|
| error level localisation | 1.70 | 2.53 | 1.70 to 1.77 |
| noise localisation | 2.86 | 3.54 | 2.83 to 3.08 |
| duplicated block fraction | 0.459 | 0.000 | 0.428 to 0.469 |

**Only error level localisation is scored.** Noise and duplication are computed
and carried as diagnostics but deliberately not scored, because the measurement
above shows they do not discriminate. Scoring a signal that does not separate
buys false escalations and nothing else.

**Why the other forgeries are invisible, and what that is not.** It is not
evidence that they are undetectable. The specimens are lossless images, edited
losslessly and saved losslessly, so there is no compression history for these
techniques to find an inconsistency in. `recapture` is the only generator that
introduces a compression round trip — which is exactly what these techniques
read. Making the rest measurable is a change to `datagen`, modelling a real
capture chain where a document is photographed as JPEG, edited and re-saved. It
is not a change to this detector.

**The constants below are calibrated on synthetic data**, and are the first
thing to re-measure against real captures — exactly like the strip locator's
density threshold. A detector that has only ever seen this repository's own
output has not been validated.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Final

from core.contracts import DOCUMENT_ROLE, Artefact, Evidence, Result, Rung, Subject
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "tamper_classical/1.0.0"

SUSPICION_THRESHOLD: Final[float] = 0.55
"""Above this the case is escalated. Genuine measures 0.35, a recapture 0.77."""

ELA_BASELINE: Final[float] = 1.0
"""Localisation of a perfectly uniform image. The score measures distance above this."""

ELA_RANGE: Final[float] = 2.0
"""Scales localisation into [0, 1]."""

TEXTURE_FLOOR: Final[float] = 8.0
"""Blocks flatter than this are blank paper.

Including them makes every ratio degenerate: the median block variance goes to
zero and the denominator becomes noise. The first version of this detector did
include them and escalated 100% of genuine documents as a result.
"""

RECOMPRESSION_QUALITY: Final[int] = 90
"""Quality used for the error level analysis pass."""

BLOCK: Final[int] = 32
"""Side of the square blocks used for every block-wise measurement."""

IMAGE_MEDIA_PREFIX: Final[str] = "image/"


@dataclass(frozen=True)
class Signals:
    """The three raw measurements, before any is turned into a score."""

    error_level: float
    """How far the worst-recompressing blocks sit above the typical one."""

    noise_inconsistency: float
    """The same localisation, over high-pass variance. Diagnostic only."""

    duplication: float
    """Fraction of textured blocks that duplicate another block. Diagnostic only."""


def _measure(image: Any) -> Signals:  # noqa: ANN401 - a NumPy array
    """Compute the three classical signals over a document image."""
    import cv2
    import numpy as np

    grey = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _ok, encoded = cv2.imencode(
        ".jpg", image, [int(cv2.IMWRITE_JPEG_QUALITY), RECOMPRESSION_QUALITY]
    )
    residual = cv2.absdiff(image, cv2.imdecode(encoded, cv2.IMREAD_COLOR)).max(axis=2)
    high_pass = cv2.Laplacian(grey, cv2.CV_64F)

    height, width = grey.shape
    error_levels: list[float] = []
    noise_levels: list[float] = []
    blocks: list[bytes] = []
    for row in range(height // BLOCK):
        for column in range(width // BLOCK):
            top, left = row * BLOCK, column * BLOCK
            patch = grey[top : top + BLOCK, left : left + BLOCK]
            if float(patch.std()) < TEXTURE_FLOOR:
                continue
            error_levels.append(float(residual[top : top + BLOCK, left : left + BLOCK].mean()))
            noise_levels.append(float(high_pass[top : top + BLOCK, left : left + BLOCK].var()))
            blocks.append((patch // 8).tobytes())

    if len(blocks) < 8:
        return Signals(0.0, 0.0, 0.0)

    def localisation(values: list[float]) -> float:
        """How far the worst blocks sit above the typical one."""
        return float(np.percentile(values, 95)) / (float(np.median(values)) + 1e-3)

    seen: dict[bytes, int] = {}
    duplicates = 0
    for key in blocks:
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            duplicates += 1

    return Signals(
        error_level=localisation(error_levels),
        noise_inconsistency=localisation(noise_levels),
        duplication=duplicates / len(blocks),
    )


@register
class ClassicalTamperDetector(Detector):
    """Looks for recompression artefacts. Escalates only; never clears."""

    id = "rung2.tamper_classical"
    rung = Rung.INFERENCE

    @staticmethod
    def _document(subject: Subject) -> Artefact | None:
        """Return the document if it is an image. No other artefact is examined here."""
        document = subject.artefact(DOCUMENT_ROLE)
        if document is None or not document.media_type.startswith(IMAGE_MEDIA_PREFIX):
            return None
        return document

    def applies_to(self, subject: Subject) -> bool:
        """Report whether the document is an image to analyse."""
        return self._document(subject) is not None

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Measure the classical signals and report suspicion, never authenticity."""
        started = time.perf_counter()
        artefact = self._document(subject)
        if artefact is None:
            return ()

        try:
            from extraction.preprocess import decode

            signals = _measure(decode(artefact.data))
        except Exception:  # a failing analysis is a result, not a crash
            return (
                self._evidence(
                    Result.INCONCLUSIVE,
                    (
                        "The image could not be analysed for signs of alteration, so "
                        "nothing was established about it either way.",
                    ),
                    None,
                    None,
                    artefact.sha256,
                    started,
                ),
            )

        # Only error level localisation is scored. See the module docstring.
        score = min(1.0, max(0.0, (signals.error_level - ELA_BASELINE) / ELA_RANGE))

        if score > SUSPICION_THRESHOLD:
            return (
                self._evidence(
                    Result.SUSPICIOUS,
                    (
                        "Parts of this image look like they were saved or compressed "
                        "separately from the rest, which is what a photograph of a "
                        "printout or a screen tends to look like.",
                        "This is a machine's impression, not proof. It cannot by "
                        "itself mean the document is false, and a person should look "
                        "at it.",
                    ),
                    score,
                    0.4,
                    artefact.sha256,
                    started,
                ),
            )

        return (
            self._evidence(
                Result.NO_FINDING,
                (
                    "An automated check for signs of alteration raised nothing. This "
                    "is not proof that the document is genuine.",
                ),
                score,
                0.4,
                artefact.sha256,
                started,
            ),
        )

    def _evidence(
        self,
        result: Result,
        reasons: tuple[str, ...],
        score: float | None,
        uncertainty: float | None,
        digest: str,
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
            input_digest=digest,
        )


def build() -> Detector:
    """Construct the classical image-tamper detector."""
    return ClassicalTamperDetector()
