"""The database connection, and the two things it always does.

SQLite in WAL mode, per the stack in CLAUDE.md. WAL matters at a checkpoint:
without it a reader blocks a writer, and an officer console refreshing a case
list would stall the screening that is writing to it.

Every session produced here carries the guard from :mod:`db.guards`. It is
attached at the factory rather than left to callers, because a guard you have
to remember to attach is a guard that is missing from the one place it was
needed.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry

from db import guards
from db.models import Base


def _enable_wal(engine: Engine) -> None:
    """Put every SQLite connection into WAL mode as it is opened."""

    @event.listens_for(engine, "connect")
    def _on_connect(connection: DBAPIConnection, _record: ConnectionPoolEntry) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def create_session_factory(url: str, *, create: bool = False) -> sessionmaker[Session]:
    """Return a configured session factory.

    Args:
        url: A SQLAlchemy URL. SQLite is what a checkpoint runs.
        create: Whether to create the schema. A deployment uses migrations; this
            exists so a test can start from an empty database.

    Returns:
        The factory. Every session it produces refuses to write a raw document
        number.
    """
    engine = create_engine(url, future=True)
    if url.startswith("sqlite"):
        _enable_wal(engine)
    if create:
        Base.metadata.create_all(engine)

    factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    guards.install(factory)
    return factory
