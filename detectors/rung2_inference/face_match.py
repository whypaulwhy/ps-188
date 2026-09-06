"""Rung 2 detector: does the document portrait match the person presenting it?

The attack this answers is the one every other rung is blind to. A genuine,
correctly signed, unexpired document presented by someone who is not its holder
passes every cryptographic and deterministic check there is. Only a comparison
between the portrait and the bearer notices, and that comparison is inference.

**It can only escalate.** A face comparison never clears a document and never
rejects one. `score` is suspicion — a larger number means the faces look *less*
alike — so it can only move a case toward a human.

**It currently reports `INCONCLUSIVE` on every document**, for two reasons, and
the second is the harder one:

1. There are no model weights here. InsightFace `buffalo_l` is a large download
   and none is present, exactly as with TruFor.
2. **There are no faces to compare.** `datagen` draws a flat placeholder panel
   rather than a portrait, deliberately: producing images of people who do not
   exist in order to test a border system is a line this project does not
   cross. So even with weights, there is nothing here to validate against.

The second blocker is not solved by a download. Validating face matching needs a
corpus of real faces, and obtaining one is a question of lawful basis and
consent before it is a question of data. `docs/scope.md` records the constraint.

**Nothing here treats an embedding as anonymous.** Any embedding this detector
produces goes through :mod:`core.privacy.biometrics`, which encrypts it at rest
under a key separate from the identifier hashing key and carries a retention
window the code enforces. See rule 4 of CLAUDE.md.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject, ZoneName
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "face_match/unavailable"
WEIGHTS_ENV: Final[str] = "SENTINELID_FACE_WEIGHTS"
LIVE_CAPTURE_ROLE: Final[str] = "live_capture"

MODEL_UNAVAILABLE: Final[str] = (
    "The face comparison model is not installed at this checkpoint, so the "
    "photograph on this document was not compared with the person presenting it. "
    "Nothing about who is holding this document was established."
)
NO_LIVE_CAPTURE: Final[str] = (
    "No photograph of the person presenting this document was taken, so there was "
    "nothing to compare the picture on it against."
)


def weights_path() -> Path | None:
    """Return the configured face model weights, or None if there are none.

    Returns:
        The weights file, or None. None is this deployment's normal state.
    """
    configured = os.environ.get(WEIGHTS_ENV)
    if not configured:
        return None
    candidate = Path(configured)
    return candidate if candidate.is_file() else None


@register
class FaceMatchDetector(Detector):
    """Compares the document portrait with a live capture of the bearer."""

    id = "rung2.face_match"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Returns true even when there is no live capture, so that the officer is
        told the bearer was not checked rather than being shown nothing at all.
        A document that was never compared against its holder is a materially
        different case from one that was.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Compare the portrait with the live capture, or say why it could not."""
        started = time.perf_counter()
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256

        if weights_path() is None:
            reason = MODEL_UNAVAILABLE
        elif subject.artefact(LIVE_CAPTURE_ROLE) is None:
            reason = NO_LIVE_CAPTURE
        elif subject.zone(ZoneName.PORTRAIT) is None:
            reason = (
                "The photograph on this document could not be located, so it was "
                "not compared with the person presenting it."
            )
        else:  # pragma: no cover - unreachable until weights and a face corpus exist
            msg = (
                "Face comparison is not written: no model weights and no lawfully "
                "obtained face corpus have ever been available to develop it "
                "against. See the module docstring."
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
    """Construct the face similarity detector."""
    return FaceMatchDetector()
