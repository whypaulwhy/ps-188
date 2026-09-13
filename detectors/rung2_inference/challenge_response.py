"""Rung 2 detector: did the person do what they were asked to do?

The liveness check next door measures whether a face changes shape between
photographs, which a flat picture cannot. A **recording** of the person can, so
a video played to the camera passes it. That is the attack this detector is for.

**The defence is that the checkpoint chooses the movements after the crossing
starts.** A recording made in advance cannot know that it will be asked for
left, then right, then left. This compares the movements asked for with the
movements the photographs actually show.

**What it does not defeat.** Someone holding clips of every movement who plays
the right one on each cue, and a live puppet of the person's face. It also says
nothing about who the person is: that is the face comparison.

**It can only escalate.** Like everything on this rung it never clears a
document and never rejects one. A person who was not asked anything is reported
as a check that could not be made, never as one that passed.

**Which way is left.** Left and right are the person's own. A head turned to the
person's left puts the nose toward the right-hand side of the picture, which is
what `direction` measures. That mapping was confirmed against photographs whose
subject said which way he had turned, not from reasoning alone.
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import LIVE_CAPTURE_ROLE, ChallengeStep, Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung2_inference import face_engine

DETECTOR_VERSION: Final[str] = "challenge_response/1.0.0+landmark-yaw"

MINIMUM_CONFIDENCE: Final[float] = 0.5
"""Below this the detector does not accept that it found a face at all."""

CENTRE_BAND: Final[float] = 0.08
"""Within this much of centre, a face is read as looking at the camera."""

TURN_BAND: Final[float] = 0.15
"""At or beyond this, a face is read as turned. Between the two is unreadable.

Both are measured as the nose's offset from the midpoint of the eyes, divided by
the width of the face, so neither depends on how close the camera was held.

**Uncalibrated.** They sit either side of what a local check on the owner's own
photographs produced, where a face-on photograph measured about zero and turned
ones measured a few tenths. No rate from that check is recorded here, because
rule 2 of CLAUDE.md admits only figures `eval/run_eval.py` produced on a named
dataset. The rates at which this escalates an honest person and misses a
recording are **TBD**.

A movement too small to read falls between the bands and is treated as not what
was asked, which escalates. That is the fail-closed answer to a measurement that
could not be made.
"""

MODEL_UNAVAILABLE: Final[str] = (
    "The check for whether the person did what they were asked is not installed at "
    "this checkpoint, so it was not made."
)
NO_LIVE_CAPTURE: Final[str] = (
    "No photograph of the person presenting this document was taken, so whether they "
    "did what they were asked was not established."
)
NOT_ASKED: Final[str] = (
    "The person was not asked to move in any particular way while being photographed, "
    "so a recording played to the camera could not be ruled out."
)
TOO_FEW: Final[str] = (
    "Fewer photographs of the person were taken than instructions were given, so "
    "whether they did what they were asked was not established."
)
NO_FACE: Final[str] = (
    "No face could be found in one of the photographs of the person, so whether they "
    "did what they were asked was not established."
)

MOVEMENTS: Final[dict[ChallengeStep, str]] = {
    ChallengeStep.CENTRE: "look at the camera",
    ChallengeStep.LEFT: "turn their head to their left",
    ChallengeStep.RIGHT: "turn their head to their right",
}
"""How each movement is written for an officer. Left and right are the person's own."""


def direction(face: face_engine.DetectedFace) -> ChallengeStep | None:
    """Return which way a face is turned, or None when it cannot be told.

    Args:
        face: A detected face, with at least the eyes and the nose.

    Returns:
        The movement the face shows, or None when the landmarks are missing or
        the turn is too slight to call.
    """
    if len(face.keypoints) < 3:
        return None
    left_eye, right_eye, nose = face.keypoints[0], face.keypoints[1], face.keypoints[2]
    width = abs(face.box[2] - face.box[0])
    if width <= 0:
        return None

    offset = (nose[0] - (left_eye[0] + right_eye[0]) / 2.0) / width
    if abs(offset) < CENTRE_BAND:
        return ChallengeStep.CENTRE
    if offset >= TURN_BAND:
        return ChallengeStep.LEFT
    if offset <= -TURN_BAND:
        return ChallengeStep.RIGHT
    return None


def asked_for(steps: tuple[ChallengeStep, ...]) -> str:
    """Return the sequence of movements as a sentence an officer can read."""
    return "The person was asked to " + ", then ".join(MOVEMENTS[step] for step in steps) + "."


@register
class ChallengeResponseDetector(Detector):
    """Checks the photographs against the movements the checkpoint asked for."""

    id = "rung2.challenge_response"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Returns true even when nobody was asked anything, so that a crossing
        where a recording could not be ruled out reads differently from one
        where it could.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Compare what was asked with what the photographs show."""
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

        asked = subject.liveness_challenge
        if not asked:
            return Result.INCONCLUSIVE, None, (NOT_ASKED,)
        if len(captures) < len(asked):
            return Result.INCONCLUSIVE, None, (TOO_FEW,)

        observed: list[ChallengeStep | None] = []
        for capture in captures[: len(asked)]:
            found = [
                face
                for face in face_engine.faces(capture.data)
                if face.confidence >= MINIMUM_CONFIDENCE
            ]
            if not found:
                return Result.INCONCLUSIVE, None, (NO_FACE,)
            observed.append(direction(found[0]))

        if observed == list(asked):
            return (
                Result.NO_FINDING,
                0.0,
                (
                    f"{asked_for(asked)} That is what the photographs show.",
                    "This does not establish that a real person was present. Someone "
                    "holding a recording of every movement, played on cue, could do the "
                    "same, and this checkpoint has no check that would notice.",
                ),
            )
        return (
            Result.SUSPICIOUS,
            1.0,
            (
                f"{asked_for(asked)} The photographs do not show that.",
                "This is a machine's impression, not proof. A person who moved too "
                "little, or who misunderstood, looks the same as a recording played to "
                "the camera. Ask them again, or check in person that they are present.",
            ),
        )


def build() -> Detector:
    """Construct the challenge and response detector."""
    return ChallengeResponseDetector()
