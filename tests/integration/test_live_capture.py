"""Photographs of the person, from the page that takes them to the checks that read them.

Phase 19 gave the face checks something to read. Three properties are pinned here.

**The photographs arrive, in the order they were taken.** The face engine is
replaced by a stand-in for this. There are no faces in this repository, by
decision, so what is tested is the wiring and not recognition.

**What the checkpoint asked for reaches the check that verifies it.** A screening
that quotes a challenge is compared with the movements that challenge asked for,
and one challenge answers exactly one screening.

**Sending more files cannot change which file the document checks read.** Before
phase 19 a screening carried one file, so "the first PDF" and "the document"
were the same thing. With photographs of the person alongside, they are not: a
signed file sent as a photograph of the person would have been verified as
though it were the document, and could have cleared the case.
"""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
from collections.abc import Iterator
from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from api.app import app_for
from api.challenge import STEPS
from api.screening import Deployment, screen
from api.settings import Settings
from core.contracts import ChallengeStep, Decision, Provenance, Result, Verdict
from detectors.rung2_inference import challenge_response, face_engine, face_match, pad_liveness
from tests.golden.harness import CASES_DIR, FIXTURE_CAPTURED_AT, GoldenCase, load_case

CHECKPOINT_ID: Final[str] = "raxaul-03"

DOCUMENT: Final[bytes] = b"this stands for a photograph of a document"
LOOKING: Final[bytes] = b"the person, looking at the camera"
TURNED: Final[bytes] = b"the person, head turned a little"
STRANGER: Final[bytes] = b"somebody else entirely"
THEIR_LEFT: Final[bytes] = b"the person, turned to their left"
THEIR_RIGHT: Final[bytes] = b"the person, turned to their right"

EYES_NOSE_MOUTH: Final[tuple[tuple[float, float], ...]] = (
    (40.0, 40.0),
    (80.0, 40.0),
    (60.0, 60.0),
    (45.0, 80.0),
    (75.0, 80.0),
)
NOSE_MOVED: Final[tuple[tuple[float, float], ...]] = (
    (40.0, 40.0),
    (80.0, 40.0),
    (75.0, 60.0),
    (45.0, 80.0),
    (75.0, 80.0),
)
"""The same face with the nose shifted toward one eye, as a head turning does."""

HOLDER: Final[tuple[float, ...]] = (1.0, 0.0)
SOMEONE_ELSE: Final[tuple[float, ...]] = (0.0, 1.0)


def _face(
    points: tuple[tuple[float, float], ...], identity: tuple[float, ...]
) -> face_engine.DetectedFace:
    """Return a detected face with chosen landmarks and a chosen identity."""
    return face_engine.DetectedFace(
        box=(0.0, 0.0, 120.0, 120.0), confidence=0.9, keypoints=points, embedding=identity
    )


def _turned(offset: float) -> face_engine.DetectedFace:
    """Return the holder's face with the nose that far across the face, as a turn."""
    points = (
        (40.0, 40.0),
        (80.0, 40.0),
        (60.0 + offset * 120.0, 60.0),
        (45.0, 80.0),
        (75.0, 80.0),
    )
    return _face(points, HOLDER)


FACES: Final[dict[bytes, tuple[face_engine.DetectedFace, ...]]] = {
    DOCUMENT: (_face(EYES_NOSE_MOUTH, HOLDER),),
    LOOKING: (_face(EYES_NOSE_MOUTH, HOLDER),),
    TURNED: (_face(NOSE_MOVED, HOLDER),),
    STRANGER: (_face(EYES_NOSE_MOUTH, SOMEONE_ELSE),),
    THEIR_LEFT: (_turned(0.25),),
    THEIR_RIGHT: (_turned(-0.25),),
}
"""What the stand-in engine finds in each file. The portrait on the document is the holder."""

STEP_PHOTOGRAPHS: Final[dict[str, bytes]] = {
    ChallengeStep.CENTRE.value: LOOKING,
    ChallengeStep.LEFT.value: THEIR_LEFT,
    ChallengeStep.RIGHT.value: THEIR_RIGHT,
}
"""A photograph that answers each movement a challenge can ask for."""

THE_OTHER_WAY: Final[dict[str, str]] = {
    ChallengeStep.CENTRE.value: ChallengeStep.CENTRE.value,
    ChallengeStep.LEFT.value: ChallengeStep.RIGHT.value,
    ChallengeStep.RIGHT.value: ChallengeStep.LEFT.value,
}
"""Turning the wrong way, which is what a recording of an earlier crossing does."""

SIGNED: Final[GoldenCase] = load_case(CASES_DIR / "pdf-signature-valid")
"""A signed PDF that verifies against the anchor its golden case names."""


@pytest.fixture
def stand_in_faces(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the face engine with one that finds the faces in `FACES`."""
    monkeypatch.setattr(face_engine, "available", lambda: True)
    monkeypatch.setattr(face_engine, "faces", lambda data: FACES.get(data, ()))


@pytest.fixture
def without_face_models(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment never given the face models, whatever this machine happens to hold."""
    monkeypatch.delenv(face_engine.MODEL_ROOT_ENV, raising=False)
    face_engine.reset_cache()


@pytest.fixture
def settings(tmp_path: pathlib.Path) -> Settings:
    """A deployment on a database of its own."""
    return Settings(
        database_url=f"sqlite+pysqlite:///{(tmp_path / 'live.db').as_posix()}",
        checkpoint_id=CHECKPOINT_ID,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A client over the API and the console, sharing one deployment."""
    with TestClient(app_for(settings, create=True)) as opened:
        yield opened


def document_and(*photographs: bytes) -> list[tuple[str, tuple[str, bytes, str]]]:
    """Return the files for one document and photographs of the person, in order."""
    files = [("capture", ("document.png", DOCUMENT, "image/png"))]
    files.extend(
        ("live_capture", (f"person-{number}.jpg", data, "image/jpeg"))
        for number, data in enumerate(photographs, start=1)
    )
    return files


def screened_over_http(
    client: TestClient, *photographs: bytes, challenge_id: str | None = None
) -> dict[str, Any]:
    """Submit a document and photographs of the person, and return the case."""
    response = client.post(
        "/screenings",
        files=document_and(*photographs),
        data={"challenge_id": challenge_id} if challenge_id else None,
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def answering(client: TestClient, *, correctly: bool = True) -> dict[str, Any]:
    """Ask for a challenge, then answer it with photographs that do or do not match."""
    challenge = client.post("/liveness/challenge").json()
    asked = challenge["steps"]
    order = asked if correctly else [THE_OTHER_WAY[step] for step in asked]
    return screened_over_http(
        client, *[STEP_PHOTOGRAPHS[step] for step in order], challenge_id=challenge["challenge_id"]
    )


def found(body: dict[str, Any]) -> list[str]:
    """Return every sentence the officer reads under "What was found"."""
    return [line for finding in body["findings"] for line in finding["detail"]]


# The photographs arrive


def test_photographs_of_the_person_reach_both_face_checks(
    client: TestClient, stand_in_faces: None
) -> None:
    """The criterion for this phase: the bearer is no longer reported as unphotographed."""
    body = screened_over_http(client, LOOKING, TURNED)

    assert any("consistent with the photograph on it" in line for line in found(body))
    assert any("changed shape between photographs" in line for line in found(body))
    assert face_match.NO_LIVE_CAPTURE not in body["not_checked"]
    assert pad_liveness.NO_LIVE_CAPTURE not in body["not_checked"]


def test_without_photographs_the_case_says_the_person_was_not_checked(
    client: TestClient, stand_in_faces: None
) -> None:
    """Screening the document alone is allowed, and is never silent about the person."""
    body = screened_over_http(client)

    assert face_match.NO_LIVE_CAPTURE in body["not_checked"]
    assert pad_liveness.NO_LIVE_CAPTURE in body["not_checked"]


def test_one_photograph_is_compared_but_cannot_show_a_person_was_there(
    client: TestClient, stand_in_faces: None
) -> None:
    """Where the capture page's "only one photograph" button leads."""
    body = screened_over_http(client, LOOKING)

    assert any("consistent with the photograph on it" in line for line in found(body))
    assert pad_liveness.SINGLE_FRAME in body["not_checked"]


def test_the_first_photograph_is_the_one_compared_with_the_document(
    client: TestClient, stand_in_faces: None
) -> None:
    """The capture page asks for the face-on photograph first, so the order must survive."""
    body = screened_over_http(client, STRANGER, LOOKING)

    assert body["decision"] == Decision.MANUAL_REVIEW.value
    assert any("does not look like the photograph on it" in line for line in found(body))


def test_an_empty_photograph_is_not_counted_as_one(
    client: TestClient, stand_in_faces: None
) -> None:
    """An empty part is a form with nothing chosen, not a photograph of nobody."""
    response = client.post(
        "/screenings",
        files=[
            ("capture", ("document.png", DOCUMENT, "image/png")),
            ("live_capture", ("person-1.jpg", b"", "image/jpeg")),
        ],
    )

    assert response.status_code == 201
    assert face_match.NO_LIVE_CAPTURE in response.json()["not_checked"]


def test_too_many_photographs_are_refused(settings: Settings) -> None:
    """A policy limit, and the refusal says what it is."""
    limited = dataclasses.replace(settings, max_live_captures=2)
    with TestClient(app_for(limited, create=True)) as client:
        response = client.post("/screenings", files=document_and(LOOKING, TURNED, LOOKING))

    assert response.status_code == 422
    assert "At most 2 photographs" in response.json()["detail"]


def test_an_oversized_photograph_is_refused(settings: Settings) -> None:
    """The document's limit applies to each photograph, for the same reason."""
    limited = dataclasses.replace(settings, max_upload_bytes=len(DOCUMENT))
    with TestClient(app_for(limited, create=True)) as client:
        response = client.post("/screenings", files=document_and(b"x" * (len(DOCUMENT) + 1)))

    assert response.status_code == 413


# What the checkpoint asked for


def test_a_challenge_asks_for_movements_starting_face_on(client: TestClient) -> None:
    """The first photograph is the one the face comparison uses."""
    body = client.post("/liveness/challenge").json()

    assert len(body["steps"]) == STEPS
    assert body["steps"][0] == ChallengeStep.CENTRE.value
    assert body["challenge_id"]


def test_doing_what_was_asked_is_reported(client: TestClient, stand_in_faces: None) -> None:
    """The photographs answer the movements this checkpoint chose for this crossing."""
    body = answering(client, correctly=True)

    assert any("That is what the photographs show" in line for line in found(body))


def test_doing_something_else_is_escalated(client: TestClient, stand_in_faces: None) -> None:
    """The attack: a recording that turns the way it turned when it was recorded."""
    body = answering(client, correctly=False)

    assert body["decision"] == Decision.MANUAL_REVIEW.value
    assert any("The photographs do not show that" in line for line in found(body))


def test_photographs_with_no_challenge_say_so(client: TestClient, stand_in_faces: None) -> None:
    """Sending photographs without asking for a challenge establishes nothing."""
    body = screened_over_http(client, LOOKING, TURNED)

    assert challenge_response.NOT_ASKED in body["not_checked"]


def test_one_challenge_answers_one_screening(client: TestClient, stand_in_faces: None) -> None:
    """A captured identifier must be worth nothing the second time."""
    challenge = client.post("/liveness/challenge").json()
    photographs = [STEP_PHOTOGRAPHS[step] for step in challenge["steps"]]

    screened_over_http(client, *photographs, challenge_id=challenge["challenge_id"])
    again = screened_over_http(client, *photographs, challenge_id=challenge["challenge_id"])

    assert challenge_response.NOT_ASKED in again["not_checked"]


# The console


def test_the_capture_page_photographs_the_person(client: TestClient) -> None:
    """The front camera, and the instruction the liveness check depends on."""
    text = client.get("/console/capture").text

    assert 'capture="user"' in text
    assert "turn their head" in text
    assert "live_capture" in text


def test_the_capture_page_asks_the_checkpoint_what_to_ask_for(client: TestClient) -> None:
    """The page must not invent the movements; a recording could then match them."""
    text = client.get("/console/capture").text

    assert "/liveness/challenge" in text
    assert "Turn your head to your left." in text


def test_the_capture_page_takes_the_person_from_live_video_where_it_can(
    client: TestClient,
) -> None:
    """Live video where the browser allows it, photographs one at a time where it does not."""
    # Whitespace collapsed: a sentence in the page may be wrapped across lines.
    text = " ".join(client.get("/console/capture").text.split())

    assert "getUserMedia" in text
    assert 'id="live"' in text
    assert "Photograph them one at a time instead" in text
    assert "Only still photographs are sent" in text


def test_the_capture_page_says_plainly_when_the_checkpoint_cannot_be_reached(
    client: TestClient,
) -> None:
    """A browser's own wording for a lost connection means nothing to an officer."""
    assert "The checkpoint could not be reached." in client.get("/console/capture").text


def test_the_upload_form_takes_photographs_of_the_person(client: TestClient) -> None:
    """The fallback with no network: photographs taken earlier, sent from the laptop."""
    text = client.get("/console/submit").text

    assert 'name="live_capture"' in text
    assert "multiple" in text


def test_photographs_uploaded_from_the_console_reach_the_face_checks(
    client: TestClient, stand_in_faces: None
) -> None:
    """The same wiring, through the form that needs no JavaScript."""
    response = client.post(
        "/console/submit", files=document_and(LOOKING, TURNED), follow_redirects=False
    )

    assert response.status_code == 303
    page = client.get(response.headers["location"]).text
    assert "changed shape between photographs" in page
    assert face_match.NO_LIVE_CAPTURE not in page


def test_too_many_photographs_from_the_console_are_refused_with_a_reason(
    settings: Settings,
) -> None:
    """An officer is told what to change, not shown an error code."""
    limited = dataclasses.replace(settings, max_live_captures=2)
    with TestClient(app_for(limited, create=True)) as client:
        response = client.post(
            "/console/submit",
            files=document_and(LOOKING, TURNED, LOOKING),
            follow_redirects=False,
        )

    assert response.status_code == 422
    assert "At most 2 photographs" in response.text


def test_an_oversized_photograph_from_the_console_is_refused_with_a_reason(
    settings: Settings,
) -> None:
    """The same limit as the document, explained the same way."""
    limited = dataclasses.replace(settings, max_upload_bytes=len(DOCUMENT))
    with TestClient(app_for(limited, create=True)) as client:
        response = client.post(
            "/console/submit",
            files=document_and(b"x" * (len(DOCUMENT) + 1)),
            follow_redirects=False,
        )

    assert response.status_code == 422
    assert "photographs of the person is larger" in response.text


# The document checks read the document


def screened_directly(
    document: bytes, media_type: str, *, people: tuple[tuple[bytes, str], ...] = ()
) -> Verdict:
    """Screen through the real pipeline, against the anchor the signed file verifies with."""
    store = SIGNED.trust_store()
    settings = Settings(database_url="sqlite://", checkpoint_id="golden-corpus", trust_store=store)
    _, verdict = screen(
        document,
        provenance=Provenance(
            source_id="smuggling",
            sha256=hashlib.sha256(document).hexdigest(),
            media_type=media_type,
            byte_size=len(document),
            captured_at=FIXTURE_CAPTURED_AT,
            received_at=FIXTURE_CAPTURED_AT,
            checkpoint_id="golden-corpus",
        ),
        deployment=Deployment(settings=settings, trust_store=store),
        decided_at=FIXTURE_CAPTURED_AT,
        live_captures=people,
    )
    return verdict


def signature_results(verdict: Verdict) -> list[Result]:
    """Return what the PDF signature check reported, if it examined anything."""
    return [item.result for item in verdict.evidence if item.detector_id == "rung0.pdf_pkcs7"]


def test_the_signed_file_verifies_when_it_is_the_document(without_face_models: None) -> None:
    """The control. Without it, the test below could pass on a file that never verifies."""
    verdict = screened_directly(SIGNED.input_path.read_bytes(), "application/pdf")

    assert signature_results(verdict) == [Result.PROOF_VALID]


def test_a_signed_file_sent_as_a_photograph_of_the_person_is_not_verified(
    without_face_models: None,
) -> None:
    """The attack this phase opened until the document checks were changed.

    The document is unreadable, and a genuinely signed file arrives labelled as a
    photograph of the person. Verified as though it were the document, it would
    clear a case whose actual document was never checked at all.
    """
    signed = SIGNED.input_path.read_bytes()
    verdict = screened_directly(DOCUMENT, "image/png", people=((signed, "application/pdf"),))

    assert signature_results(verdict) == []
    assert verdict.decision is not Decision.CLEARED
