"""Rung 2 detector: is the live capture a person, or a picture of one?

Presentation attack detection. The attacks are a printed photograph held to the
camera, a replay from a phone screen, and a mask. All three defeat face
matching completely, because the face being matched is the right face — it is
simply not present.

**It can only escalate.** A presentation attack detector never clears anyone and
never rejects anyone. `score` is suspicion, so a larger number moves a case
toward a human and nowhere else.

**It currently reports `INCONCLUSIVE` on every capture.** There are no model
weights here, and there is no live capture in this project to reason about:
`datagen` produces documents, not photographs of people. Both blockers are the
same as `face_match`, and the second is again the harder one, because
validating this needs recordings of real people making real presentation
attacks.

**What this detector must never do** is treat the absence of an attack signal as
evidence of a live person. `NO_FINDING` means it looked and raised nothing. It
does not mean the person is there.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "pad_liveness/unavailable"
WEIGHTS_ENV: Final[str] = "SENTINELID_PAD_WEIGHTS"
LIVE_CAPTURE_ROLE: Final[str] = "live_capture"

MODEL_UNAVAILABLE: Final[str] = (
    "The check for whether the camera was shown a real person rather than a "
    "photograph is not installed at this checkpoint, so it was not made."
)
NO_LIVE_CAPTURE: Final[str] = (
    "No photograph of the person presenting this document was taken, so there was nothing to check."
)


def weights_path() -> Path | None:
    """Return the configured presentation attack model, or None if there is none."""
    configured = os.environ.get(WEIGHTS_ENV)
    if not configured:
        return None
    candidate = Path(configured)
    return candidate if candidate.is_file() else None


@register
class PresentationAttackDetector(Detector):
    """Judges whether a live capture shows a person or a reproduction of one."""

    id = "rung2.pad_liveness"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        A crossing where no live capture was taken is reported as one where the
        bearer was not checked, rather than passing in silence.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Judge the live capture, or say why it could not be judged."""
        started = time.perf_counter()
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256

        if weights_path() is None:
            reason = MODEL_UNAVAILABLE
        elif subject.artefact(LIVE_CAPTURE_ROLE) is None:
            reason = NO_LIVE_CAPTURE
        else:  # pragma: no cover - unreachable until weights and a corpus exist
            msg = (
                "Presentation attack detection is not written: no model weights and "
                "no lawfully obtained corpus of attacks have ever been available to "
                "develop it against. See the module docstring."
            )
            raise NotImplementedError(msg)

        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=Result.INCONCLUSIVE,
                reasons=(reason,),
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )


def build() -> Detector:
    """Construct the presentation attack detection detector."""
    return PresentationAttackDetector()
