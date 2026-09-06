"""The officer console, driven the way an officer drives it.

Two things are being checked. The first is that the honesty rule survives the
trip into HTML: what was not checked has to be on the page, on every case, not
behind a disclosure triangle and not dropped because the list happened to be
empty.

The second is escaping. Detector reasons can quote text read off a document,
which means part of the page is chosen by whoever presents the document. The
last tests here put markup into a stored verdict and check it arrives as text.
"""

from __future__ import annotations

import datetime
import pathlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from api.app import app_for
from api.settings import NO_LEDGER_KEY, Settings
from core.contracts import Decision, Evidence, Result, Rung, Verdict
from core.standards.verhoeff import verhoeff_digit
from core.trust.ladder import resolve
from db.recording import load_case, record_screening
from db.session import create_session_factory
from tests.support import DECIDED_AT, provenance

CHECKPOINT_ID = "raxaul-03"
WHEN = datetime.datetime(2026, 9, 7, 11, 0, tzinfo=datetime.UTC)
MARKUP = '<script>alert("x")</script>'


@pytest.fixture
def settings(tmp_path: pathlib.Path) -> Settings:
    """A deployment with no keys, so the queue also shows its own gaps."""
    return Settings(
        database_url=f"sqlite+pysqlite:///{(tmp_path / 'console.db').as_posix()}",
        checkpoint_id=CHECKPOINT_ID,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A client over the console and the API sharing one deployment."""
    with TestClient(app_for(settings, create=True)) as opened:
        yield opened


def unresolved(reason: str | None = None) -> Verdict:
    """Return a verdict that needs a person, optionally with chosen text in it."""
    item = Evidence(
        detector_id="rung2.tamper_classical",
        rung=Rung.INFERENCE,
        result=Result.SUSPICIOUS,
        reasons=(reason or "Part of the photograph looks different from the rest.",),
        score=0.5,
        uncertainty=0.2,
        runtime_ms=4.0,
        model_version="classical/1",
        input_digest="a" * 64,
    )
    return resolve([item], provenance=provenance(), decided_at=DECIDED_AT)


def seed(settings: Settings, case_id: str, verdict: Verdict | None = None) -> str:
    """Write one case straight to storage, bypassing the capture path."""
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        record_screening(
            session,
            case_id=case_id,
            verdict=verdict if verdict is not None else unresolved(),
            checkpoint_id=CHECKPOINT_ID,
            recorded_at=WHEN,
        )
    return case_id


def test_the_queue_renders(client: TestClient, settings: Settings) -> None:
    """The first screen of the shift."""
    seed(settings, "case-1")
    response = client.get("/console/")

    assert response.status_code == 200
    assert "case-1" in response.text
    assert "Waiting for a person (1)" in response.text


def test_the_queue_states_what_this_checkpoint_cannot_do(client: TestClient) -> None:
    """On the front page, not in a log file nobody at the border reads."""
    assert NO_LEDGER_KEY in client.get("/console/").text


def test_an_empty_queue_does_not_claim_everything_was_checked(client: TestClient) -> None:
    """An empty queue is not a claim that nothing was wrong, and the page says so."""
    text = client.get("/console/").text

    assert "not a statement that every crossing was checked" in text


def test_a_case_page_states_what_was_not_checked(client: TestClient, settings: Settings) -> None:
    """The honesty rule, in HTML. Under the decision, on every case."""
    seed(settings, "case-1")
    text = client.get("/console/case/case-1").text

    assert "What was not checked" in text
    for line in unresolved().not_checked:
        assert line in text


def without_styles(page: str) -> str:
    """Return the page without its stylesheet.

    The stylesheet is full of numbers like `0.5rem`, and a test looking for a
    score would find one there. What matters is what an officer reads.
    """
    head, _, rest = page.partition("<style>")
    _, _, tail = rest.partition("</style>")
    return head + tail


def test_a_case_page_shows_no_score(client: TestClient, settings: Settings) -> None:
    """The evidence behind this case carries one. The page must not."""
    seed(settings, "case-1")
    text = without_styles(client.get("/console/case/case-1").text).lower()

    assert "0.5" not in text
    assert "uncertainty" not in text
    assert "score" not in text


def test_a_case_page_offers_a_decision(client: TestClient, settings: Settings) -> None:
    """The work the queue exists for."""
    text = client.get(f"/console/case/{seed(settings, 'case-1')}").text

    assert "Record this decision" in text
    assert 'name="officer_id"' in text
    assert 'value="CLEARED"' in text
    assert 'value="MANUAL_REVIEW"' not in text


def test_an_unknown_case_says_what_that_means(client: TestClient) -> None:
    """A missing case must not read as one that was cleared, rejected or deleted."""
    response = client.get("/console/case/no-such-case")

    assert response.status_code == 404
    assert "not the same as the case having been cleared" in response.text


def test_recording_a_decision_redirects_and_sticks(client: TestClient, settings: Settings) -> None:
    """A redirect after the write, so a refresh cannot submit a second review."""
    case_id = seed(settings, "case-1")
    response = client.post(
        f"/console/case/{case_id}/review",
        data={
            "officer_id": "officer-12",
            "outcome": "CLEARED",
            "note": "Bearer produced a second document and the photograph matches.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    text = client.get(f"/console/case/{case_id}").text
    assert "officer-12" in text
    assert "Bearer produced a second document" in text


def test_an_override_is_marked_as_one(client: TestClient, settings: Settings) -> None:
    """An officer clearing what the checks could not is worth showing as such."""
    case_id = seed(settings, "case-1")
    client.post(
        f"/console/case/{case_id}/review",
        data={
            "officer_id": "officer-12",
            "outcome": "CLEARED",
            "note": "Bearer produced a second document and the photograph matches.",
        },
    )

    text = client.get(f"/console/case/{case_id}").text
    assert "That record is unchanged" in text
    assert "MANUAL REVIEW" in text


def test_a_decision_without_a_reason_is_refused(client: TestClient, settings: Settings) -> None:
    """And the officer is told what is missing, not shown a stack trace."""
    case_id = seed(settings, "case-1")
    response = client.post(
        f"/console/case/{case_id}/review",
        data={"officer_id": "officer-12", "outcome": "CLEARED", "note": "   "},
    )

    assert response.status_code == 422
    assert "a note saying why" in response.text


def test_a_note_holding_a_document_number_is_refused(
    client: TestClient, settings: Settings
) -> None:
    """Rule 3, as advice to the officer rather than a silent edit of their note."""
    case_id = seed(settings, "case-1")
    body = "23456789012"
    response = client.post(
        f"/console/case/{case_id}/review",
        data={
            "officer_id": "officer-12",
            "outcome": "CLEARED",
            "note": f"Bearer quoted {body + verhoeff_digit(body)} at the counter.",
        },
    )

    assert response.status_code == 422
    assert "document number" in response.text

    factory = create_session_factory(settings.database_url)
    with factory() as session:
        view = load_case(session, case_id)
    assert view is not None
    assert view.reviews == ()
    assert view.standing_decision is Decision.MANUAL_REVIEW


def test_reviewing_an_unknown_case_is_refused(client: TestClient) -> None:
    """A decision recorded against nothing is a decision about nothing."""
    response = client.post(
        "/console/case/no-such-case/review",
        data={"officer_id": "officer-12", "outcome": "CLEARED", "note": "Looked at it."},
    )

    assert response.status_code == 404


def test_text_from_a_document_is_escaped(client: TestClient, settings: Settings) -> None:
    """Part of this page is chosen by whoever presents the document.

    A detector reason can quote what it read. If that reached the browser as
    markup, a prepared document would be running script in an officer's session
    at a border post.
    """
    seed(settings, "case-1", unresolved(f"The name field reads {MARKUP} on the strip."))
    text = client.get("/console/case/case-1").text

    assert MARKUP not in text
    assert "&lt;script&gt;" in text


def test_an_officers_own_words_are_escaped(client: TestClient, settings: Settings) -> None:
    """The other untrusted input on the page, and the one that persists."""
    case_id = seed(settings, "case-1")
    client.post(
        f"/console/case/{case_id}/review",
        data={"officer_id": "officer-12", "outcome": "CLEARED", "note": f"Saw {MARKUP} on it."},
    )

    text = client.get(f"/console/case/{case_id}").text
    assert MARKUP not in text
    assert "&lt;script&gt;" in text


def test_the_console_and_the_api_share_one_deployment(
    client: TestClient, settings: Settings
) -> None:
    """A case recorded through one surface has to be visible from the other."""
    case_id = seed(settings, "case-1")
    client.post(
        f"/cases/{case_id}/reviews",
        json={
            "officer_id": "officer-12",
            "outcome": "REJECTED",
            "note": "The photograph is not the bearer.",
        },
    )

    assert "officer-12" in client.get(f"/console/case/{case_id}").text
