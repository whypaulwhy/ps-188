"""Face comparison and liveness: contract, not accuracy.

`CLAUDE.md` is explicit that a Rung 2 detector is never tested for accuracy in a
unit test — correct shape, no exception on malformed input, `INCONCLUSIVE` when
the model is unavailable. That is doubly right here: there is no lawfully
obtained corpus of faces or of presentation attacks in this project, so there is
nothing to measure accuracy against and any number claimed would be invented.

What is tested is everything that does not need a face: the arithmetic of the
two scores, that absence is reported honestly rather than guessed at, and that
neither detector can say anything a Rung 2 detector is not allowed to say.
"""

from __future__ import annotations

import datetime
import math
from typing import Final

import pytest

from core.contracts import Artefact, DocumentType, Provenance, Result, Rung, Subject
from detectors.rung2_inference import face_engine, face_match, pad_liveness

NOW: Final[datetime.datetime] = datetime.datetime(2026, 9, 10, 12, 0, tzinfo=datetime.UTC)
DIGEST: Final[str] = "c" * 64
NOT_AN_IMAGE: Final[bytes] = b"this is not an image"


def subject(*roles: str, data: bytes = NOT_AN_IMAGE) -> Subject:
    """Build a subject carrying one artefact per named role."""
    return Subject(
        provenance=Provenance(
            source_id="case-face",
            sha256=DIGEST,
            media_type="image/png",
            byte_size=len(data),
            captured_at=NOW,
            received_at=NOW,
            checkpoint_id="ssb-demo-01",
        ),
        declared_type=DocumentType.UNRECOGNISED,
        artefacts=tuple(
            Artefact(role=role, media_type="image/png", sha256=DIGEST, data=data) for role in roles
        ),
    )


@pytest.fixture
def without_models(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment that was never given the face models. The normal state."""
    monkeypatch.delenv(face_engine.MODEL_ROOT_ENV, raising=False)
    face_engine.reset_cache()


# Absence is reported, never guessed at


def test_face_match_abstains_without_models(without_models: None) -> None:
    """The condition CLAUDE.md names for a Rung 2 detector."""
    evidence = face_match.build().run(subject("document_front", "live_capture"))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.score is None
    assert "not installed" in evidence.reasons[0]


def test_liveness_abstains_without_models(without_models: None) -> None:
    """Same condition, same answer."""
    evidence = pad_liveness.build().run(subject("live_capture", "live_capture"))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert "not installed" in evidence.reasons[0]


def test_a_missing_model_directory_is_not_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """A path that names nothing is the same as no path at all."""
    monkeypatch.setenv(face_engine.MODEL_ROOT_ENV, "D:/nowhere/at/all")
    face_engine.reset_cache()

    assert face_engine.available() is False
    assert face_engine.model_root() is None


def test_faces_returns_nothing_when_unavailable(without_models: None) -> None:
    """The engine never raises for want of a model."""
    assert face_engine.faces(NOT_AN_IMAGE) == ()


# The scores


@pytest.mark.parametrize(
    ("similarity", "expected"),
    [(1.0, 0.0), (0.0, 0.5), (-1.0, 1.0), (0.5, 0.25)],
)
def test_suspicion_points_toward_a_person(similarity: float, expected: float) -> None:
    """A bigger score always means a human should look.

    Every Rung 2 score in this system points the same way, so faces that are
    alike must score low rather than high.
    """
    assert face_match.suspicion(similarity) == pytest.approx(expected)


def test_suspicion_is_bounded() -> None:
    """A similarity outside its range must not produce a score outside [0, 1]."""
    assert face_match.suspicion(3.0) == 0.0
    assert face_match.suspicion(-3.0) == 1.0


FIVE: Final[tuple[tuple[float, float], ...]] = (
    (40.0, 40.0),
    (80.0, 40.0),
    (60.0, 60.0),
    (45.0, 80.0),
    (75.0, 80.0),
)
"""Two eyes, a nose and two mouth corners, roughly where a detector puts them."""

TURNED: Final[tuple[tuple[float, float], ...]] = (
    (40.0, 40.0),
    (80.0, 40.0),
    (75.0, 60.0),
    (45.0, 80.0),
    (75.0, 80.0),
)
"""The same face with the nose shifted toward one eye, as a head turning does."""


def face_with(points: tuple[tuple[float, float], ...]) -> face_engine.DetectedFace:
    """Wrap landmarks in a detected face. Only the landmarks matter here."""
    return face_engine.DetectedFace(
        box=(0.0, 0.0, 120.0, 120.0), confidence=0.9, keypoints=points, embedding=(1.0,)
    )


def rigidly(
    points: tuple[tuple[float, float], ...],
    *,
    dx: float = 0.0,
    dy: float = 0.0,
    degrees: float = 0.0,
    scale: float = 1.0,
) -> tuple[tuple[float, float], ...]:
    """Move a face the way a hand moves a photograph: shift, turn, bring closer."""
    angle = math.radians(degrees)
    cos, sin = math.cos(angle), math.sin(angle)
    return tuple(
        (scale * (x * cos - y * sin) + dx, scale * (x * sin + y * cos) + dy) for x, y in points
    )


def test_a_perfectly_still_face_does_not_change_shape() -> None:
    """The baseline: nothing moved, nothing changed."""
    assert pad_liveness.movement([face_with(FIVE), face_with(FIVE)]) == pytest.approx(0.0, abs=1e-9)


@pytest.mark.parametrize(
    ("dx", "dy", "degrees", "scale"),
    [(25.0, -10.0, 0.0, 1.0), (0.0, 0.0, 8.0, 1.0), (0.0, 0.0, 0.0, 1.3), (-30.0, 15.0, -6.0, 0.8)],
)
def test_moving_a_photograph_rigidly_is_not_movement(
    dx: float, dy: float, degrees: float, scale: float
) -> None:
    """The attack that defeated the first version of this detector.

    A photograph held up in a hand shifts, turns and comes closer, and every
    landmark moves with it. The first version measured that movement and let
    the photograph pass. What must be measured is change of shape, and a flat
    photograph has none however it is held.
    """
    moved = rigidly(FIVE, dx=dx, dy=dy, degrees=degrees, scale=scale)

    assert pad_liveness.movement([face_with(FIVE), face_with(moved)]) < (
        pad_liveness.STILLNESS_THRESHOLD
    )


def test_a_head_turning_changes_shape() -> None:
    """The nose moving relative to the eyes is what a real head does in 3D."""
    assert pad_liveness.movement([face_with(FIVE), face_with(TURNED)]) > (
        pad_liveness.STILLNESS_THRESHOLD
    )


def test_a_turning_head_is_not_hidden_by_the_camera_moving_too() -> None:
    """A real head turning while the camera shakes must still read as a head turning."""
    shaken = rigidly(TURNED, dx=18.0, dy=-7.0, degrees=4.0, scale=1.1)

    assert pad_liveness.movement([face_with(FIVE), face_with(shaken)]) > (
        pad_liveness.STILLNESS_THRESHOLD
    )


def test_the_measure_does_not_depend_on_how_close_the_camera_was() -> None:
    """The same turn close to the camera must not read as more of a turn."""
    far = pad_liveness.movement([face_with(FIVE), face_with(TURNED)])
    near = pad_liveness.movement(
        [face_with(rigidly(FIVE, scale=2.5)), face_with(rigidly(TURNED, scale=2.5))]
    )

    assert near == pytest.approx(far)


def test_too_few_landmarks_cannot_show_movement() -> None:
    """Two points have a position but no shape, so no change of shape can be seen.

    Reported as still, which escalates: the fail-closed answer to a measurement
    that could not be made.
    """
    two = ((10.0, 10.0), (20.0, 10.0))
    elsewhere = ((40.0, 40.0), (90.0, 10.0))

    assert pad_liveness.movement([face_with(two), face_with(elsewhere)]) == 0.0


def test_landmarks_that_coincide_cannot_show_movement() -> None:
    """A degenerate detection has no shape either."""
    collapsed = ((50.0, 50.0), (50.0, 50.0), (50.0, 50.0))

    assert pad_liveness.movement([face_with(collapsed), face_with(FIVE[:3])]) == 0.0


def test_a_mirror_image_is_not_accepted_as_the_same_face() -> None:
    """Only proper rotations are removed. A reflection is not a head movement."""
    mirrored = tuple((120.0 - x, y) for x, y in TURNED)

    assert pad_liveness.movement([face_with(TURNED), face_with(mirrored)]) > 0.0


# What each detector refuses to conclude


def test_liveness_refuses_to_judge_a_single_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """A still image of a still image looks exactly like a still image of a person."""
    monkeypatch.setattr(face_engine, "available", lambda: True)

    evidence = pad_liveness.build().run(subject("live_capture"))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert "single photograph cannot show" in evidence.reasons[0]


def test_liveness_says_nothing_when_the_bearer_was_never_photographed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crossing where nobody was checked must read differently from one where they were."""
    monkeypatch.setattr(face_engine, "available", lambda: True)

    evidence = pad_liveness.build().run(subject("document_front"))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert "No photograph of the person" in evidence.reasons[0]


def test_face_match_says_nothing_without_a_live_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """There is nothing to compare the document against."""
    monkeypatch.setattr(face_engine, "available", lambda: True)

    evidence = face_match.build().run(subject("document_front"))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert "nothing to compare" in evidence.reasons[0]


def test_unreadable_captures_do_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bytes that are not an image are a bad scan, not an exception."""
    monkeypatch.setattr(face_engine, "available", lambda: True)
    monkeypatch.setattr(face_engine, "faces", lambda _data: ())

    for detector in (face_match.build(), pad_liveness.build()):
        evidence = detector.run(subject("document_front", "live_capture", "live_capture"))[0]
        assert evidence.result is Result.INCONCLUSIVE


# What a Rung 2 detector may never say


def test_neither_detector_can_clear_a_document(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole reason face comparison sits on Rung 2 rather than Rung 0."""
    monkeypatch.setattr(face_engine, "available", lambda: True)

    for detector in (face_match.build(), pad_liveness.build()):
        evidence = detector.run(subject("document_front", "live_capture"))[0]
        assert evidence.rung is Rung.INFERENCE
        assert evidence.result is not Result.PASS
        assert evidence.result is not Result.PROOF_VALID
