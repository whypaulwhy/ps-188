"""The shell, driven the way a checkpoint drives it.

A capture goes in over HTTP, a case comes back, an officer records a decision,
and a third party verifies the log using nothing but the API's own responses.
That last one is the point of the whole ledger, and it is tested here rather
than argued about: the checkpoint and the proof are fetched over HTTP and
verified with the published key, without touching the database.

The screenings below mostly submit bytes that are not an image. That is
deliberate on two counts. It keeps the suite fast, and an unreadable capture is
the case that must never be quietly dropped — a border that ignores malformed
input has a gap in it exactly where someone would push.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import pathlib
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi.testclient import TestClient

from api import routes
from api.app import app_for
from api.screening import Deployment, assemble
from api.settings import NO_HASH_KEY, NO_LEDGER_KEY, Settings
from core.privacy.hashing import DeploymentKey
from core.privacy.retention import ArtefactCategory, RetentionPolicy
from core.standards.verhoeff import verhoeff_digit
from datagen.synthetic_docs import generate_specimen
from db.recording import recent_cases
from db.session import create_session_factory
from detectors.base import registered
from explain.renderer import NOT_CHECKED_HEADING
from ledger.hashchain import Checkpoint, verify_checkpoint, verify_inclusion
from tests.support import one_anchor_store

CHECKPOINT_ID = "raxaul-03"
GARBAGE = b"this is not a document"


@pytest.fixture(scope="module")
def signing_key() -> Ed25519PrivateKey:
    """One signing key for the module, so checkpoints are comparable."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def settings(tmp_path: pathlib.Path, signing_key: Ed25519PrivateKey) -> Settings:
    """A fully equipped deployment on a database of its own."""
    return Settings(
        database_url=f"sqlite+pysqlite:///{(tmp_path / 'api.db').as_posix()}",
        checkpoint_id=CHECKPOINT_ID,
        hash_key=DeploymentKey(b"k" * 32),
        ledger_key=signing_key,
        trust_store=one_anchor_store(tmp_path),
        retention_policy=RetentionPolicy(
            windows={
                ArtefactCategory.FACE_EMBEDDING: datetime.timedelta(days=7),
                ArtefactCategory.PORTRAIT_CROP: datetime.timedelta(days=7),
                ArtefactCategory.DOCUMENT_IMAGE: datetime.timedelta(days=14),
                ArtefactCategory.EVIDENCE_EXHIBIT: datetime.timedelta(days=14),
                ArtefactCategory.CASE_RECORD: datetime.timedelta(days=30),
                ArtefactCategory.LEDGER_ENTRY: datetime.timedelta(days=3650),
            }
        ),
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A client over a fully equipped deployment."""
    with TestClient(app_for(settings, create=True)) as opened:
        yield opened


@pytest.fixture
def bare_client(tmp_path: pathlib.Path) -> Iterator[TestClient]:
    """A client over a deployment with no keys at all."""
    unequipped = Settings(
        database_url=f"sqlite+pysqlite:///{(tmp_path / 'bare.db').as_posix()}",
        checkpoint_id=CHECKPOINT_ID,
    )
    with TestClient(app_for(unequipped, create=True)) as opened:
        yield opened


def screen(client: TestClient, payload: bytes = GARBAGE) -> dict[str, object]:
    """Submit one capture and return the case."""
    response = client.post("/screenings", files={"capture": ("front.png", payload, "image/png")})
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def test_every_registered_detector_is_assembled(settings: Settings) -> None:
    """A detector that exists and never runs is silence about a check.

    The registry is the list of detectors this system has. If one is registered
    but the deployment never builds it, no case will ever mention it — not even
    to say it did not run.
    """
    assembled = {detector.id for detector in assemble(Deployment(settings=settings))}

    assert {detector.id for detector in registered()} == assembled


def test_health_states_what_is_missing(bare_client: TestClient) -> None:
    """A health check that only says "ok" cannot report an unmounted key."""
    body = bare_client.get("/health").json()

    assert body["checkpoint_id"] == CHECKPOINT_ID
    assert NO_LEDGER_KEY in body["unavailable"]
    assert NO_HASH_KEY in body["unavailable"]


def test_health_on_an_equipped_checkpoint_reports_nothing_missing(client: TestClient) -> None:
    """The other half, so the test above is not passing on a broken deployment."""
    body = client.get("/health").json()

    assert body["unavailable"] == []
    assert len(body["detectors"]) == len(registered())


def test_a_screening_returns_what_was_not_checked(client: TestClient) -> None:
    """The honesty rule, at the HTTP boundary. A JSON body is a report."""
    body = screen(client)

    # Spelled out because this failed once, during a loaded run, and could not be
    # reproduced in four more. A bare `assert body["not_checked"]` says nothing
    # about which of the two claims broke or what the case actually contained, so
    # the one observation was unusable. If it happens again, this will say why.
    assert body["not_checked"], (
        f"a screening of unreadable bytes listed nothing as unchecked. "
        f"decision={body.get('decision')!r} report={str(body.get('report'))[:400]!r}"
    )
    assert NOT_CHECKED_HEADING in str(body["report"]), (
        f"the report omitted the {NOT_CHECKED_HEADING!r} section. "
        f"report={str(body.get('report'))[:400]!r}"
    )


def test_a_real_document_is_screened_end_to_end(client: TestClient) -> None:
    """One full pass over an actual image, so the fast cases stand for something."""
    body = screen(client, generate_specimen(seed=1).png)

    assert body["decision"] in {"CLEARED", "MANUAL_REVIEW", "REJECTED"}
    assert body["basis"]
    assert body["leaf_index"] == 0


def test_an_unreadable_capture_still_produces_a_case(client: TestClient) -> None:
    """Not a 400. A dropped capture is a crossing nobody has a record of."""
    body = screen(client)

    assert body["decision"] == "MANUAL_REVIEW"
    assert body["awaiting_review"] is True
    assert body["not_extracted"]


def test_an_oversized_capture_is_refused(settings: Settings) -> None:
    """A checkpoint on a slow link must not be occupied by one upload."""
    limited = dataclasses.replace(settings, max_upload_bytes=1024)
    with TestClient(app_for(limited, create=True)) as client:
        response = client.post(
            "/screenings", files={"capture": ("big.png", b"x" * 1025, "image/png")}
        )

    assert response.status_code == 413


def test_an_unknown_document_type_is_refused(client: TestClient) -> None:
    """A declared type nothing recognises is a client bug, not an unknown document."""
    response = client.post(
        "/screenings",
        files={"capture": ("front.png", GARBAGE, "image/png")},
        data={"declared_type": "MOON_PASSPORT"},
    )

    assert response.status_code == 422


def test_no_score_reaches_the_wire(client: TestClient) -> None:
    """Scores stay in the stored evidence. On the wire they become a dashboard."""
    body = json.dumps(screen(client, generate_specimen(seed=1).png)).lower()

    assert "score" not in body
    assert "uncertainty" not in body


def test_a_case_can_be_read_back(client: TestClient) -> None:
    """What the officer opens after the traveller has moved down the queue."""
    case_id = str(screen(client)["case_id"])
    body = client.get(f"/cases/{case_id}").json()

    assert body["case_id"] == case_id
    assert NOT_CHECKED_HEADING in body["report"]


def test_the_report_is_available_as_text(client: TestClient) -> None:
    """The thing that gets printed and put in a file."""
    case_id = str(screen(client)["case_id"])
    response = client.get(f"/cases/{case_id}/report")

    assert response.status_code == 200
    assert NOT_CHECKED_HEADING in response.text


def test_an_unknown_case_is_a_404(client: TestClient) -> None:
    """Absent, not empty. An empty case would render as one with no findings."""
    assert client.get("/cases/no-such-case").status_code == 404
    assert client.get("/cases/no-such-case/report").status_code == 404


def test_cases_are_listed_newest_first(client: TestClient) -> None:
    """The queue an officer works from."""
    identifiers = [str(screen(client)["case_id"]) for _ in range(3)]
    listed = [case["case_id"] for case in client.get("/cases").json()]

    assert listed == list(reversed(identifiers))


def test_an_officer_can_clear_a_case_the_system_would_not(client: TestClient) -> None:
    """The purpose of manual review, and the verdict is untouched by it."""
    case_id = str(screen(client)["case_id"])
    response = client.post(
        f"/cases/{case_id}/reviews",
        json={
            "officer_id": "officer-12",
            "outcome": "CLEARED",
            "note": "Bearer produced a second document and the photograph matches.",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["decision"] == "MANUAL_REVIEW"
    assert body["standing_decision"] == "CLEARED"
    assert body["reviews"][0]["overrides_the_system"] is True
    assert body["awaiting_review"] is False


def test_a_review_cannot_conclude_manual_review(client: TestClient) -> None:
    """Otherwise a queue could be emptied without anything being decided."""
    case_id = str(screen(client)["case_id"])
    response = client.post(
        f"/cases/{case_id}/reviews",
        json={"officer_id": "officer-12", "outcome": "MANUAL_REVIEW", "note": "Not sure."},
    )

    assert response.status_code == 422


def test_a_review_without_a_reason_is_refused(client: TestClient) -> None:
    """A note is required, including for a rejection."""
    case_id = str(screen(client)["case_id"])
    response = client.post(
        f"/cases/{case_id}/reviews",
        json={"officer_id": "officer-12", "outcome": "REJECTED", "note": ""},
    )

    assert response.status_code == 422


def test_a_note_holding_a_document_number_is_refused(client: TestClient) -> None:
    """Rule 3 reaches the officer as advice, not as a silent edit of their note."""
    case_id = str(screen(client)["case_id"])
    body = "23456789012"
    response = client.post(
        f"/cases/{case_id}/reviews",
        json={
            "officer_id": "officer-12",
            "outcome": "CLEARED",
            "note": f"Bearer quoted {body + verhoeff_digit(body)} at the counter.",
        },
    )

    assert response.status_code == 422
    assert "document number" in response.json()["detail"]
    assert client.get(f"/cases/{case_id}").json()["reviews"] == []


def test_reviewing_an_unknown_case_is_a_404(client: TestClient) -> None:
    """A review recorded against nothing would be a decision about nothing."""
    response = client.post(
        "/cases/no-such-case/reviews",
        json={"officer_id": "officer-12", "outcome": "CLEARED", "note": "Looked at it."},
    )

    assert response.status_code == 404


def test_a_checkpoint_is_refused_without_a_signing_key(bare_client: TestClient) -> None:
    """An ephemeral signature would look exactly like proof, and be none."""
    response = bare_client.get("/ledger/checkpoint")

    assert response.status_code == 503
    assert "no signing key" in response.json()["detail"]


def test_a_third_party_can_verify_the_log_from_the_api_alone(client: TestClient) -> None:
    """The whole point of the ledger, exercised as an outsider would.

    Everything used here arrives over HTTP: the signed checkpoint, the public
    key, the leaf and its proof. Nothing touches the database, and the
    verification functions are the ones anyone can run.
    """
    case = screen(client)
    signed = client.get("/ledger/checkpoint").json()
    proof = client.get(f"/ledger/proof/{case['leaf_index']}").json()

    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signed["public_key"]))
    checkpoint = Checkpoint(
        tree_size=signed["tree_size"],
        root=bytes.fromhex(signed["root"]),
        signed_at=datetime.datetime.fromisoformat(signed["signed_at"]),
        signature=bytes.fromhex(signed["signature"]),
    )

    assert verify_checkpoint(checkpoint, key=public)
    assert verify_inclusion(
        bytes.fromhex(proof["leaf"]),
        index=proof["leaf_index"],
        size=checkpoint.tree_size,
        proof=tuple(bytes.fromhex(sibling) for sibling in proof["proof"]),
        root=checkpoint.root,
    )


def test_a_proof_outside_the_log_is_a_404(client: TestClient) -> None:
    """Asking for a proof of something absent is an error, not an empty proof."""
    assert client.get("/ledger/proof/99").status_code == 404


def test_an_unhandled_failure_is_answered_as_a_refusal(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one interpretation that must never be available is "nothing was wrong".

    An empty 500 leaves that open. This returns 503 and says the document is
    unscreened, so a client cannot read silence as a clean result.

    `raise_server_exceptions=False` makes the test client behave like a real
    one: Starlette re-raises after the handler has produced its response, so
    that the server logs the failure, and only the response crosses the wire.
    """

    def explode(*_args: object, **_kwargs: object) -> None:
        msg = "the database fell over"
        raise RuntimeError(msg)

    monkeypatch.setattr(routes, "load_case", explode)
    with TestClient(app_for(settings, create=True), raise_server_exceptions=False) as client:
        response = client.get("/cases/anything")

    assert response.status_code == 503
    assert "unscreened" in response.json()["detail"]


def test_the_database_is_the_one_the_settings_name(settings: Settings) -> None:
    """A second database created by a default path is the failure this guards."""
    with TestClient(app_for(settings, create=True)) as opened:
        screen(opened)

    factory = create_session_factory(settings.database_url)
    with factory() as session:
        assert len(recent_cases(session)) == 1
