"""Rung 2 detector: is the live capture a person, or a picture of one?

Presentation attack detection. The attacks are a printed photograph held to the
camera, a replay from a phone screen, and a mask. All three defeat face matching
completely, because the face being matched is the right face — it is simply not
present.

**It can only escalate.** A presentation attack detector never clears anyone and
never rejects anyone. `score` is suspicion, so a larger number moves a case
toward a human and nowhere else.

**What it measures is change of shape, not change of position.** There is no
trained anti-spoofing model here, so this does not attempt one. It takes several
frames a moment apart and, for each pair, aligns the five facial landmarks by
orthogonal Procrustes — removing translation, rotation and scale — and measures
what is left: how much the *arrangement* of eyes, nose and mouth changed. A flat
photograph keeps its arrangement however it is moved, tilted or brought closer.
A real head turning in three dimensions projects to a different arrangement.

**The first version got this wrong, and said the opposite.** It measured how far
the landmarks moved. A photograph held in a hand moves every landmark — shake,
tilt, drift — so it read as a face that moved, and passed, while this docstring
claimed it defeated a printed photograph. Phase 18 of `docs/roadmap.md` records
how it was found. The tests below pin the property that was missing: moving a
face rigidly is not movement.

**What it still does not defeat:** a video replay, which changes shape because
the recorded head did; and a photograph *bent* between frames, since bending
changes its shape. It has not been tried against a real printed photograph
filmed by a real camera. The officer wording says what was established and no
more, because "the liveness check passed" will otherwise be read as far more.

**It needs the head to turn.** A person holding perfectly still is escalated,
which is the safe direction and a nuisance at a barrier, so whatever takes the
live frames must ask the bearer to turn their head slowly.

**A single frame establishes nothing.** Given one photograph this reports
`INCONCLUSIVE`, because there is no change to measure.

**What this detector must never do** is treat the absence of an attack signal as
evidence of a live person. `NO_FINDING` means it looked and raised nothing. It
does not mean the person is there.
"""

from __future__ import annotations

import itertools
import time
from typing import Final

import numpy as np

from core.contracts import LIVE_CAPTURE_ROLE, Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung2_inference import face_engine

DETECTOR_VERSION: Final[str] = "pad_liveness/2.0.0+landmark-geometry"
"""Bumped from 1.x because the measure changed meaning.

`model_version` is part of what the ledger digests, so a case decided under the
old measure and replayed under this one is correctly reported as a different
basis for the decision rather than as the same one.
"""

MINIMUM_FRAMES: Final[int] = 2
"""Fewer than this and there is no change to measure."""

MINIMUM_KEYPOINTS: Final[int] = 3
"""Fewer points than this have no shape, only a position."""

STILLNESS_THRESHOLD: Final[float] = 0.07
"""Below this change of shape the capture is treated as a flat picture.

Measured as the Procrustes residual between frames after both are centred and
scaled to unit size, so it is unitless and does not depend on how close the
camera was held.

**Uncalibrated.** It sits, on a log scale, between what photographs moved
rigidly produced in a local check and what a deliberate head turn produced — a
check run on the owner's own images, held outside the repository, whose figures
are not recorded here because rule 2 of CLAUDE.md admits only figures produced
by `eval/run_eval.py` on a named dataset. The rates at which this escalates a
live person and misses a presentation attack are **TBD**.

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


def _geometry_change(
    earlier: tuple[tuple[float, float], ...], later: tuple[tuple[float, float], ...]
) -> float:
    """Return how much the arrangement of landmarks changed between two frames.

    Both sets are centred and scaled to unit size, then the later one is rotated
    onto the earlier by orthogonal Procrustes. What remains is change of shape:
    none for a photograph moved, turned or brought closer; some for a head that
    turned in three dimensions.

    Args:
        earlier: Landmarks in the first frame.
        later: The same landmarks in the next frame, in the same order.

    Returns:
        The residual, unitless. Zero when there is no shape to compare — fewer
        than three points, a mismatched count, or points that all coincide —
        which reads as a still picture and escalates. That is the fail-closed
        answer to a measurement that could not be made.
    """
    if len(earlier) < MINIMUM_KEYPOINTS or len(earlier) != len(later):
        return 0.0

    first = np.asarray(earlier, dtype=float)
    second = np.asarray(later, dtype=float)
    first = first - first.mean(axis=0)
    second = second - second.mean(axis=0)

    first_size = float(np.sqrt((first**2).sum()))
    second_size = float(np.sqrt((second**2).sum()))
    if first_size == 0.0 or second_size == 0.0:
        return 0.0
    first = first / first_size
    second = second / second_size

    left, _, right = np.linalg.svd(second.T @ first)
    if np.linalg.det(left @ right) < 0:
        # A proper rotation only. Allowing a reflection would let a face be
        # matched to its own mirror image, which is not a movement a head makes.
        left[:, -1] *= -1
    rotation = left @ right
    return float(np.sqrt(((first - second @ rotation) ** 2).sum()))


def movement(frames: list[face_engine.DetectedFace]) -> float:
    """Return the largest change of facial shape between consecutive frames.

    Args:
        frames: The face found in each frame, in capture order.

    Returns:
        The largest Procrustes residual across consecutive pairs. Moving,
        turning or rescaling a flat photograph contributes nothing to it.
    """
    largest = 0.0
    for earlier, later in itertools.pairwise(frames):
        largest = max(largest, _geometry_change(earlier.keypoints, later.keypoints))
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

        if movement(frames) < STILLNESS_THRESHOLD:
            return (
                Result.SUSPICIOUS,
                1.0,
                (
                    "The face in front of the camera did not change shape between "
                    "photographs. It only moved as a whole, which is what a printed "
                    "photograph or a picture on a screen does, however it is held.",
                    "This is a machine's impression, not proof. Ask the person to turn "
                    "their head slowly and photograph them again, or check in person "
                    "that they are really present.",
                ),
            )
        return (
            Result.NO_FINDING,
            0.0,
            (
                "The face in front of the camera changed shape between photographs "
                "the way a turning head does, which a flat photograph held up to the "
                "camera cannot.",
                "This does not establish that a real person was present. A recording "
                "played to the camera, or a photograph bent between frames, could do "
                "the same, and this checkpoint has no check that would notice.",
            ),
        )


def build() -> Detector:
    """Construct the presentation attack detector."""
    return PadLivenessDetector()
