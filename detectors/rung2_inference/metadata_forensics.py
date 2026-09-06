"""Rung 2 detector: metadata inconsistencies in a captured image.

Reads what a file says about its own history: which software wrote it, what
dimensions it claims, when it says it was made.

**Absent metadata is not suspicious.** That is the trap this detector is written
around. A scanner, a phone screenshot and a re-saved image all routinely carry
no metadata at all, so treating its absence as a signal would flag most genuine
documents at these crossings. When there is nothing to examine, this reports
`INCONCLUSIVE` — the check did not happen — rather than `NO_FINDING`, which
would imply it looked and was satisfied.

It escalates only on **positive** evidence: a field naming an image editor.
"""

from __future__ import annotations

import io
import time
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "metadata_forensics/1.0.0"
IMAGE_MEDIA_PREFIX: Final[str] = "image/"

EDITOR_MARKERS: Final[tuple[str, ...]] = (
    "photoshop",
    "gimp",
    "paint.net",
    "pixelmator",
    "affinity",
    "lightroom",
    "snapseed",
    "picsart",
)
"""Software names indicating an image was opened in an editor and re-saved."""

NOTHING_TO_EXAMINE: Final[str] = (
    "This image carries no record of how it was made, so its history could not be "
    "checked. Most scans and photographs carry none, so this says nothing about "
    "the document."
)
UNREADABLE: Final[str] = "The record of how this image was made could not be read."


@register
class MetadataForensicsDetector(Detector):
    """Examines what an image records about its own origin."""

    id = "rung2.metadata_forensics"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether the subject carries an image."""
        return any(
            artefact.media_type.startswith(IMAGE_MEDIA_PREFIX) for artefact in subject.artefacts
        )

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Read the image's metadata and report only positive findings."""
        started = time.perf_counter()
        artefact = next(
            (a for a in subject.artefacts if a.media_type.startswith(IMAGE_MEDIA_PREFIX)), None
        )
        if artefact is None:  # pragma: no cover - guarded by applies_to
            return ()

        result, reasons, score = self._examine(artefact.data)
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                score=score,
                uncertainty=None if score is None else 0.35,
                reasons=reasons,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=artefact.sha256,
            ),
        )

    def _examine(self, data: bytes) -> tuple[Result, tuple[str, ...], float | None]:
        """Return the result, reasons and suspicion for one image."""
        try:
            from PIL import Image

            with Image.open(io.BytesIO(data)) as image:
                recorded = {
                    str(key).lower(): str(value)
                    for key, value in (image.info or {}).items()
                    if isinstance(value, str)
                }
                for tag, value in dict(image.getexif()).items():
                    recorded[f"exif:{tag}"] = str(value)
                width, height = image.size
        except Exception:  # a failure to read is a result, not a crash
            return Result.INCONCLUSIVE, (UNREADABLE,), None

        if not recorded:
            return Result.INCONCLUSIVE, (NOTHING_TO_EXAMINE,), None

        joined = " ".join(recorded.values()).lower()
        if any(marker in joined for marker in EDITOR_MARKERS):
            return (
                Result.SUSPICIOUS,
                (
                    "This image records that it was opened and re-saved in photo "
                    "editing software. That is not proof of anything on its own, and "
                    "a person should look at it.",
                ),
                0.7,
            )

        return (
            Result.NO_FINDING,
            (
                f"The record of how this image was made shows nothing unusual, and it "
                f"measures {width} by {height} as stated. This is not proof that the "
                f"document is genuine.",
            ),
            0.0,
        )


def build() -> Detector:
    """Construct the image metadata forensics detector."""
    return MetadataForensicsDetector()
