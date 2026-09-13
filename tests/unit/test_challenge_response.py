"""Did the person do what they were asked? Contract, not accuracy.

As with every Rung 2 detector, what is tested here is the shape of the answer:
that absence is reported rather than guessed at, that a mismatch escalates and a
match does not clear, and that reading a direction from landmarks means what it
says. There are no faces in this repository, so the engine is a stand-in.
"""

from __future__ import annotations

import datetime
from typing import Final

import pytest

from core.contracts import (
    DOCUMENT_ROLE,
    LIVE_CAPTURE_ROLE,
    Artefact,
    ChallengeStep,
    Provenance,
    Result,
    Rung,
    Subject,
)
from detectors.rung2_inference import challenge_response, face_engine

NOW: Final[datetime.datetime] = datetime.datetime(2026, 9, 13, 9, 0, tzinfo=datetime.UTC)
DIGEST: Final[str] = "c" * 64
WIDTH: Final[float] = 120.0

FACING: Final[bytes] = b"the person, facing the camera"
THEIR_LEFT: Final[bytes] = b"the person, turned to their left"
THEIR_RIGHT: Final[bytes] = b"the person, turned to their right"
UNREADABLE: Final[bytes] = b"a photograph with no face in it"


def face(offset: float, *, confidence: float = 0.9) -> face_engine.DetectedFace:
    """Return a face whose nose sits `offset` of the face width from centre.

    Positive puts the nose toward the right-hand side of the picture, which is
    where a head turned to the person's own left puts it.
    """
    return face_engine.DetectedFace(
        box=(0.0, 0.0, WIDTH, WIDTH),
        confidence=confidence,
        keypoints=(
            (40.0, 40.0),
            (80.0, 40.0),
            (60.0 + offset * WIDTH, 60.0),
            (45.0, 80.0),
            (75.0, 80.0),
        ),
        embedding=(1.0,),
    )


FACES: Final[dict[bytes, tuple[face_engine.DetectedFace, ...]]] = {
    FACING: (face(0.0),),
    THEIR_LEFT: (face(0.25),),
    THEIR_RIGHT: (face(-0.25),),
    UNREADABLE: (),
}


@pytest.fixture
def stand_in_faces(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the face engine with one that finds the faces in `FACES`."""
    monkeypatch.setattr(face_engine, "available", lambda: True)
    monkeypatch.setattr(face_engine, "faces", lambda data: FACES.get(data, ()))


@pytest.fixture
def without_models(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment that was never given the face models."""
    monkeypatch.delenv(face_engine.MODEL_ROOT_ENV, raising=False)
    face_engine.reset_cache()


def subject(*photographs: bytes, asked: tuple[ChallengeStep, ...] = ()) -> Subject:
    """Build a subject carrying a document, photographs, and what was asked."""
    return Subject(
        provenance=Provenance(
            source_id="case-challenge",
            sha256=DIGEST,
            media_type="image/png",
            byte_size=16,
            captured_at=NOW,
            received_at=NOW,
            checkpoint_id="ssb-demo-01",
        ),
        artefacts=(
            Artefact(role=DOCUMENT_ROLE, media_type="image/png", sha256=DIGEST, data=b"document"),
            *(
                Artefact(
                    role=LIVE_CAPTURE_ROLE, media_type="image/jpeg", sha256=DIGEST, data=photograph
                )
                for photograph in photographs
            ),
        ),
        liveness_challenge=asked,
    )


# Reading a direction from landmarks


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (0.0, ChallengeStep.CENTRE),
        (0.05, ChallengeStep.CENTRE),
        (-0.05, ChallengeStep.CENTRE),
        (0.25, ChallengeStep.LEFT),
        (-0.25, ChallengeStep.RIGHT),
    ],
)
def test_a_direction_is_read_from_where_the_nose_sits(
    offset: float, expected: ChallengeStep
) -> None:
    """A head turned to the person's left puts the nose toward the image's right."""
    assert challenge_response.direction(face(offset)) is expected


def test_a_turn_too_slight_to_call_is_not_called() -> None:
    """Between the bands the answer is unknown, which the detector escalates."""
    assert challenge_response.direction(face(0.12)) is None


def test_a_face_without_landmarks_has_no_direction() -> None:
    """Two points have a position but no nose to measure."""
    shrunk = face_engine.DetectedFace(
        box=(0.0, 0.0, WIDTH, WIDTH),
        confidence=0.9,
        keypoints=((40.0, 40.0), (80.0, 40.0)),
        embedding=(1.0,),
    )

    assert challenge_response.direction(shrunk) is None


def test_a_face_with_no_width_has_no_direction() -> None:
    """A degenerate box would divide by zero. It reads as unknown instead."""
    flat = face_engine.DetectedFace(
        box=(10.0, 0.0, 10.0, WIDTH),
        confidence=0.9,
        keypoints=((40.0, 40.0), (80.0, 40.0), (60.0, 60.0)),
        embedding=(1.0,),
    )

    assert challenge_response.direction(flat) is None


# What the detector refuses to conclude


def test_it_abstains_without_models(without_models: None) -> None:
    """The condition CLAUDE.md names for a Rung 2 detector."""
    evidence = challenge_response.build().run(subject(FACING))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert "not installed" in evidence.reasons[0]


def test_it_says_nothing_when_the_person_was_never_photographed(
    stand_in_faces: None,
) -> None:
    """A crossing where nobody was photographed reads differently from one where they were."""
    evidence = challenge_response.build().run(subject())[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.reasons[0] == challenge_response.NO_LIVE_CAPTURE


def test_photographs_without_a_challenge_establish_nothing(stand_in_faces: None) -> None:
    """The case an attacker would choose: photographs, and nothing asked of them."""
    evidence = challenge_response.build().run(subject(FACING, THEIR_LEFT))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.reasons[0] == challenge_response.NOT_ASKED


def test_fewer_photographs_than_instructions_establishes_nothing(stand_in_faces: None) -> None:
    """Half an answer is not an answer."""
    asked = (ChallengeStep.CENTRE, ChallengeStep.LEFT, ChallengeStep.RIGHT)
    evidence = challenge_response.build().run(subject(FACING, THEIR_LEFT, asked=asked))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.reasons[0] == challenge_response.TOO_FEW


def test_a_photograph_with_no_face_establishes_nothing(stand_in_faces: None) -> None:
    """A missed face is a bad photograph, not a failed instruction."""
    asked = (ChallengeStep.CENTRE, ChallengeStep.LEFT)
    evidence = challenge_response.build().run(subject(FACING, UNREADABLE, asked=asked))[0]

    assert evidence.result is Result.INCONCLUSIVE
    assert evidence.reasons[0] == challenge_response.NO_FACE


# What it concludes


def test_following_the_instructions_raises_nothing(stand_in_faces: None) -> None:
    """And says, in the same breath, what it still has not established."""
    asked = (ChallengeStep.CENTRE, ChallengeStep.LEFT, ChallengeStep.RIGHT)
    evidence = challenge_response.build().run(
        subject(FACING, THEIR_LEFT, THEIR_RIGHT, asked=asked)
    )[0]

    assert evidence.result is Result.NO_FINDING
    assert "turn their head to their left" in evidence.reasons[0]
    assert "recording" in evidence.reasons[1]


def test_the_wrong_movement_escalates(stand_in_faces: None) -> None:
    """The attack this detector exists for: a recording that turns the wrong way."""
    asked = (ChallengeStep.CENTRE, ChallengeStep.LEFT, ChallengeStep.RIGHT)
    evidence = challenge_response.build().run(
        subject(FACING, THEIR_RIGHT, THEIR_LEFT, asked=asked)
    )[0]

    assert evidence.result is Result.SUSPICIOUS
    assert "do not show that" in evidence.reasons[0]
    assert "not proof" in evidence.reasons[1]


def test_not_moving_at_all_escalates(stand_in_faces: None) -> None:
    """A recording of someone sitting still answers no challenge."""
    asked = (ChallengeStep.CENTRE, ChallengeStep.LEFT)
    evidence = challenge_response.build().run(subject(FACING, FACING, asked=asked))[0]

    assert evidence.result is Result.SUSPICIOUS


def test_it_can_neither_clear_nor_reject(stand_in_faces: None) -> None:
    """The whole reason this sits on Rung 2 rather than Rung 0."""
    asked = (ChallengeStep.CENTRE, ChallengeStep.LEFT)
    for photographs in ((FACING, THEIR_LEFT), (FACING, THEIR_RIGHT)):
        evidence = challenge_response.build().run(subject(*photographs, asked=asked))[0]

        assert evidence.rung is Rung.INFERENCE
        assert evidence.result is not Result.PASS
        assert evidence.result is not Result.PROOF_VALID
