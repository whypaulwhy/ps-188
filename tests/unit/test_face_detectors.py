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


def test_movement_of_a_perfectly_still_face_is_zero() -> None:
    """Which is what a printed photograph held to a camera looks like."""
    face = face_engine.DetectedFace(
        box=(0.0, 0.0, 100.0, 100.0),
        confidence=0.9,
        keypoints=((10.0, 10.0), (20.0, 10.0)),
        embedding=(1.0, 0.0),
    )

    assert pad_liveness.movement([face, face]) == 0.0


def test_movement_is_relative_to_the_size_of_the_face() -> None:
    """The same movement close to the camera must not read as more movement."""
    near = face_engine.DetectedFace(
        box=(0.0, 0.0, 200.0, 200.0),
        confidence=0.9,
        keypoints=((10.0, 10.0),),
        embedding=(1.0,),
    )
    near_moved = face_engine.DetectedFace(
        box=(0.0, 0.0, 200.0, 200.0),
        confidence=0.9,
        keypoints=((30.0, 10.0),),
        embedding=(1.0,),
    )
    far = face_engine.DetectedFace(
        box=(0.0, 0.0, 100.0, 100.0),
        confidence=0.9,
        keypoints=((10.0, 10.0),),
        embedding=(1.0,),
    )
    far_moved = face_engine.DetectedFace(
        box=(0.0, 0.0, 100.0, 100.0),
        confidence=0.9,
        keypoints=((20.0, 10.0),),
        embedding=(1.0,),
    )

    assert pad_liveness.movement([near, near_moved]) == pytest.approx(
        pad_liveness.movement([far, far_moved])
    )


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
