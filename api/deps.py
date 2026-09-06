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

from api.screening import Deployment
from api.settings import Settings
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
        deployment=Deployment(settings=settings),
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
