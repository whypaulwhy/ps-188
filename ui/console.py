"""The screen an officer actually works from.

Server-rendered HTML, no JavaScript, no build step. That is not minimalism for
its own sake: a checkpoint may be running on a low-powered box with no network,
and a console that needs a bundler to change a label is a console nobody at the
border can fix.

**What was not checked is on the page, not behind a click.** It sits directly
under the decision, in its own block, on every case. CLAUDE.md says silence
about a missing check is a defect; a disclosure triangle is a quieter kind of
silence.

**No score is shown anywhere.** Findings carry none by contract, and this
console never reaches past them into the evidence. An officer weighing 0.31
against 0.62 is doing the arithmetic the trust ladder exists to replace.

**Every value is escaped.** Detector reasons can quote text read off a
document, which means an attacker can choose part of it. Autoescaping is on and
the templates never mark anything safe.
"""

from __future__ import annotations

import datetime
import pathlib
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from core.contracts import Decision, OfficerReview
from db.guards import RawIdentifierError
from db.recording import (
    RecordingError,
    load_case,
    load_destruction,
    recent_cases,
    record_review,
)
from explain.renderer import render_verdict

TEMPLATES = Jinja2Templates(directory=str(pathlib.Path(__file__).parent / "templates"))
"""Autoescaping is Jinja2's default for `.html`, and nothing here turns it off."""

NOTE_HOLDS_A_NUMBER = (
    "That note appears to contain a document number. Please remove it and describe "
    "the document instead - numbers are never stored in the clear."
)

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "CONCERN": 1, "ADVISORY": 2, "INFO": 3}
"""Worst first. The officer reads top down and should not have to hunt."""


def _context_of(request: Request) -> Any:  # noqa: ANN401 - a duck-typed context
    """Return the application context, which the console shares with the API.

    Typed loosely on purpose. The console needs a `settings` and a
    `session_factory` and nothing else, and importing the API's own context
    class to say so would make the package that renders records depend on the
    package that produces them. An import-linter contract keeps it that way.
    """
    return request.scope["app"].state.context


def _base(request: Request) -> str:
    """Return the path the console is mounted at, so links survive remounting."""
    return str(request.scope.get("root_path", "")).rstrip("/")


async def queue(request: Request) -> Response:
    """Render the work queue: what needs a person, then everything else."""
    context = _context_of(request)
    with context.session_factory() as session:
        cases = recent_cases(session, limit=100)

    return TEMPLATES.TemplateResponse(
        request,
        "queue.html",
        {
            "base": _base(request),
            "checkpoint_id": context.settings.checkpoint_id,
            "unavailable": context.settings.unavailable(),
            "awaiting": [case for case in cases if case.awaiting_review],
            "settled": [case for case in cases if not case.awaiting_review],
        },
    )


def _case_page(request: Request, case_id: str, *, error: str | None = None) -> Response:
    """Render one case, or explain why it cannot be shown.

    Three outcomes, deliberately distinct: the case, a page saying it was
    destroyed under retention, or a page saying nothing by that identifier was
    ever recorded here.
    """
    context = _context_of(request)
    with context.session_factory() as session:
        view = load_case(session, case_id)

    if view is None:
        # A destroyed case and a case that never existed are different facts, and
        # an officer must be able to tell them apart. Showing "no such case" for
        # a lawful destruction would read as a record that went missing.
        with context.session_factory() as session:
            tombstone = load_destruction(session, case_id)
        if tombstone is not None:
            return TEMPLATES.TemplateResponse(
                request,
                "destroyed.html",
                {"base": _base(request), "case_id": case_id, "destruction": tombstone},
                status_code=410,
            )
        return TEMPLATES.TemplateResponse(
            request,
            "missing.html",
            {"base": _base(request), "case_id": case_id},
            status_code=404,
        )

    findings = sorted(
        view.verdict.findings, key=lambda finding: SEVERITY_ORDER.get(finding.severity.name, 9)
    )
    return TEMPLATES.TemplateResponse(
        request,
        "case.html",
        {
            "base": _base(request),
            "case": view,
            "verdict": view.verdict,
            "findings": findings,
            "report": render_verdict(view.verdict),
            "error": error,
            "outcomes": [Decision.CLEARED.value, Decision.REJECTED.value],
        },
        status_code=200 if error is None else 422,
    )


async def case(request: Request) -> Response:
    """Render one case."""
    return _case_page(request, request.path_params["case_id"])


async def review(request: Request) -> Response:
    """Record an officer's decision, then show the case again.

    A redirect follows a successful write so that refreshing the page does not
    submit a second review. A failed one re-renders the form with the reason,
    rather than discarding what the officer typed.
    """
    case_id = str(request.path_params["case_id"])
    form = await request.form()
    context = _context_of(request)
    failure: str | None = None

    with context.session_factory() as session:
        view = load_case(session, case_id)
        if view is None:
            return _case_page(request, case_id)

        try:
            decision = OfficerReview(
                case_id=case_id,
                outcome=Decision(str(form.get("outcome", ""))),
                officer_id=str(form.get("officer_id", "")).strip(),
                note=str(form.get("note", "")).strip(),
                system_decision=view.verdict.decision,
                recorded_at=datetime.datetime.now(datetime.UTC),
            )
        except ValueError:
            failure = "Please give your officer identifier, a decision, and a note saying why."
        else:
            try:
                record_review(session, decision)
            except RawIdentifierError:
                failure = NOTE_HOLDS_A_NUMBER
            except RecordingError as error:
                failure = str(error)

    if failure is not None:
        return _case_page(request, case_id, error=failure)
    return RedirectResponse(f"{_base(request)}/case/{case_id}", status_code=303)


def build_console(context: Any) -> Starlette:  # noqa: ANN401 - api.deps.Context
    """Return the officer console as a mountable application.

    Args:
        context: The application context, shared with the API so that both
            surfaces read and write the same database and see the same
            deployment.

    Returns:
        The console.
    """
    console = Starlette(
        routes=[
            Route("/", queue, name="queue"),
            Route("/case/{case_id}", case, name="case"),
            Route("/case/{case_id}/review", review, methods=["POST"], name="review"),
        ]
    )
    console.state.context = context
    return console
