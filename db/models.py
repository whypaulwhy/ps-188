"""SQLAlchemy models. Stores salted hashes and reference IDs, never a raw document number."""

from __future__ import annotations


def metadata() -> object:
    """Return the SQLAlchemy metadata for all tables. Not yet implemented."""
    raise NotImplementedError("db.models lands in phase 9")
