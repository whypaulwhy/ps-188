"""Rung 2 detector: is the live capture a person, or a picture of one?

Presentation attack detection. The attacks are a printed photograph held to the
camera, a replay from a phone screen, and a mask. All three defeat face matching
completely, because the face being matched is the right face — it is simply not
present.

**It can only escalate.** A presentation attack detector never clears anyone and
never rejects anyone. `score` is suspicion, so a larger number moves a case
toward a human and nowhere else.

**What it checks, and what that is worth.** There is no trained anti-spoofing
model here, so this does not attempt one. What it does instead is a challenge:
several frames are captured a moment apart, and a face that is genuinely present
does not hold perfectly still. A printed photograph held to a camera does. The
signal is the movement of the five facial landmarks between frames, measured
relative to the size of the face so that holding the camera closer does not read
as movement.

**This defeats a printed photograph. It does not defeat a video replay**, and it
is not a substitute for a trained model. Saying so is the point: an officer told
"the liveness check passed" will read more into it than this can carry, so the
wording says what was actually established.

**A single frame establishes nothing.** Given one photograph, this reports
`INCONCLUSIVE` rather than guessing, because there is no movement to measure and
a still image of a still image is indistinguishable from a still image of a
person. That is the honest answer and it is also the common case, so the officer
is told plainly that the bearer's presence was not established.

**What this detector must never do** is treat the absence of an attack signal as
evidence of a live person. `NO_FINDING` means it looked and raised nothing. It
does not mean the person is there.
"""

from __future__ import annotations

import itertools
import math
import time
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung2_inference import face_engine

DETECTOR_VERSION: Final[str] = "pad_liveness/1.0.0+landmark-motion"
LIVE_CAPTURE_ROLE: Final[str] = "live_capture"

MINIMUM_FRAMES: Final[int] = 2
"""Fewer than this and there is no movement to measure."""

STILLNESS_THRESHOLD: Final[float] = 0.004
"""Below this relative movement the capture is treated as a still image.

Measured as landmark displacement divided by the width of the face, so it does
not change with how close the camera was held. **Uncalibrated**: no corpus of
real presentation attacks has ever been available to this project, and rule 2 of
CLAUDE.md means no accuracy figure for it may be written until one has been.
Shipping it uncalibrated is defensible only because the rung cannot clear
anybody: a badly chosen number sends more people to an officer.
"""

MINIMUM_CONFIDENCE: Final[float] = 0.5
"""Below this the detector does not accept that it found a face at all."""

MODEL_UNAVAILABLE: Final[str] = (
    "The check for whether the camera was shown a real person rather than a "
    "photograph is not installed at this checkpoint, so it was not made."
)
NO_LIVE_CAPTURE: Final[str] = (
    "No photograph of the person presenting this document was taken, so whether a "
    "real person was in front of the camera was not established."
)
SINGLE_FRAME: Final[str] = (
    "Only one photograph of the person was taken. A single photograph cannot show "
    "whether a real person was present or whether the camera was shown a picture, "
    "so this was not established either way."
)
NO_FACE: Final[str] = (
    "No face could be found in the photographs of the person, so whether a real "
    "person was present was not established."
)


def movement(frames: list[face_engine.DetectedFace]) -> float:
    """Return how far the landmarks moved between frames, relative to face size.

    Args:
        frames: The face found in each frame, in capture order.

    Returns:
        The largest per-frame landmark displacement, divided by the width of the
        face. Dividing is what makes the number comparable between a camera held
        at arm's length and one held close.
    """
    largest = 0.0
    for earlier, later in itertools.pairwise(frames):
        width = max(1.0, earlier.box[2] - earlier.box[0])
        pairs = zip(earlier.keypoints, later.keypoints, strict=False)
        for (x1, y1), (x2, y2) in pairs:
            largest = max(largest, math.hypot(x2 - x1, y2 - y1) / width)
    return largest


@register
class PadLivenessDetector(Detector):
    """Checks whether the camera was shown a person or a picture of one."""

    id = "rung2.pad_liveness"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Returns true even when no live capture was taken, so a crossing where
        the bearer was never checked reads differently from one where they were.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Judge the live capture, or say why it could not be judged."""
        started = time.perf_counter()
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256
        result, score, reasons = self._examine(subject)
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                score=score,
                uncertainty=None if score is None else 1.0,
                reasons=reasons,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )

    def _examine(self, subject: Subject) -> tuple[Result, float | None, tuple[str, ...]]:
        """Decide the result, the score and the officer-facing reasons."""
        if not face_engine.available():
            return Result.INCONCLUSIVE, None, (MODEL_UNAVAILABLE,)

        captures = [
            artefact for artefact in subject.artefacts if artefact.role == LIVE_CAPTURE_ROLE
        ]
        if not captures:
            return Result.INCONCLUSIVE, None, (NO_LIVE_CAPTURE,)
        if len(captures) < MINIMUM_FRAMES:
            return Result.INCONCLUSIVE, None, (SINGLE_FRAME,)

        frames: list[face_engine.DetectedFace] = []
        for capture in captures:
            found = [
                face
                for face in face_engine.faces(capture.data)
                if face.confidence >= MINIMUM_CONFIDENCE
            ]
            if found:
                frames.append(found[0])

        if len(frames) < MINIMUM_FRAMES:
            return Result.INCONCLUSIVE, None, (NO_FACE,)

        moved = movement(frames)
        if moved < STILLNESS_THRESHOLD:
            return (
                Result.SUSPICIOUS,
                1.0,
                (
                    "The person in front of the camera did not move at all between "
                    "photographs, which is what a printed photograph or a picture on "
                    "a screen looks like.",
                    "This is a machine's impression, not proof. A person should check "
                    "that the bearer is really present.",
                ),
            )
        return (
            Result.NO_FINDING,
            0.0,
            (
                "The person in front of the camera moved between photographs, so it "
                "was not a printed photograph held up to it.",
                "This does not establish that a real person was present. A recording "
                "played to the camera would also move, and this checkpoint has no "
                "check that would notice.",
            ),
        )


def build() -> Detector:
    """Construct the presentation attack detector."""
    return PadLivenessDetector()
