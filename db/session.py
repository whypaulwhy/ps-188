"""SQLite engine and session factory, WAL mode enabled at connection time."""

from __future__ import annotations


def create_session_factory(url: str) -> object:
    """Return a configured SQLAlchemy session factory. Not yet implemented."""
    raise NotImplementedError("db.session lands in phase 9")
