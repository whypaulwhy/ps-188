"""Salted, per-deployment hashing of document numbers so raw identifiers are never stored."""

from __future__ import annotations


def hash_document_number(number: str, *, salt: bytes) -> str:
    """Return the salted digest persisted in place of a raw number. Not yet implemented."""
    raise NotImplementedError("core.privacy.hashing lands in phase 3")
