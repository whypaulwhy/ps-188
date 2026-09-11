"""What a request needs, assembled once at start-up rather than per call.

A screening needs the deployment's trust store, context and keys; a write needs
a session factory. Building those per request would re-read key files on every
crossing and rebuild the detector list thousands of times a day, so they are
built once and held on the application state.

The database session is the exception: one per request, closed when it ends.
Sharing a session across requests shares a transaction, and two crossings would
be able to roll each other back.
"""

from __future__ import annotations

import dataclasses
import datetime
import secrets
from collections.abc import Iterator
from typing import Final

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker

from api.intake import Intake, record_capture
from api.screening import Deployment
from api.settings import Settings
from core.contracts import DocumentType
from db.session import create_session_factory

CASE_ID_BYTES: Final[int] = 5
"""Random bytes in a case identifier.

Ten hex characters, so a checkpoint seeing thousands of crossings a day has a
negligible chance of a collision — and a collision is refused by
:func:`db.recording.record_screening` rather than overwriting anything.
"""


@dataclasses.dataclass(frozen=True)
class Context:
    """Everything the routes need, built once."""

    settings: Settings
    deployment: Deployment
    session_factory: sessionmaker[Session]

    def screen_capture(
        self,
        session: Session,
        captured: bytes,
        *,
        now: datetime.datetime,
        media_type: str | None = None,
        declared_type: DocumentType = DocumentType.UNRECOGNISED,
        live_captures: tuple[tuple[bytes, str | None], ...] = (),
    ) -> Intake:
        """Screen one capture and record it, allocating the case identifier.

        This exists so the officer console can accept an upload without
        importing anything from `api`, `detectors` or `extraction` — an
        import-linter contract forbids it, and the console is written against a
        duck-typed context for exactly this reason. The console calls this; it
        does not know what is behind it.

        Args:
            session: An open session. The write is committed.
            captured: The document exactly as received.
            now: One clock read, shared by every record of this case.
            media_type: What the browser said the file was.
            declared_type: What the document claims to be, when known.
            live_captures: Photographs of the person, in the order taken, each
                with what the browser said it was.

        Returns:
            The case identifier, the subject and the verdict.

        Raises:
            RecordingError: If the case could not be written.
        """
        return record_capture(
            session,
            captured,
            case_id=new_case_id(now=now),
            settings=self.settings,
            deployment=self.deployment,
            now=now,
            media_type=media_type,
            declared_type=declared_type,
            live_captures=live_captures,
        )


def build_context(settings: Settings, *, create: bool = False) -> Context:
    """Assemble the application context from settings.

    Args:
        settings: The deployment's configuration.
        create: Whether to create the schema. A deployment migrates with
            Alembic; this exists so a test can start from an empty database.

    Returns:
        The context.
    """
    return Context(
        settings=settings,
        deployment=Deployment(settings=settings, trust_store=settings.trust_store),
        session_factory=create_session_factory(settings.database_url, create=create),
    )


def get_context(request: Request) -> Context:
    """Return the application context held on the app state."""
    context: Context = request.app.state.context
    return context


def get_session(request: Request) -> Iterator[Session]:
    """Yield one database session for the duration of a request."""
    context: Context = request.app.state.context
    with context.session_factory() as session:
        yield session


def new_case_id(*, now: datetime.datetime) -> str:
    """Return an opaque case identifier.

    Dated, so an officer can say one out loud and a supervisor can find it, and
    random after that. The date is UTC, like every other timestamp in this
    system; at a checkpoint several hours ahead of UTC an early-morning case
    therefore carries the previous day. One clock everywhere is worth more than
    a case identifier that reads naturally and an audit record that does not.

    It is never derived from anything on the document: a case identifier that
    encoded a document number would put one in every URL, every access log and
    every browser history.

    Args:
        now: The instant the case was opened.

    Returns:
        The identifier, of the form ``2026-09-07-A3F91C4D2B``.
    """
    return f"{now.date().isoformat()}-{secrets.token_hex(CASE_ID_BYTES).upper()}"
