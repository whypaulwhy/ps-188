"""Backend-agnostic transparency log interface that every ledger implementation satisfies."""

from __future__ import annotations


def append_entry(payload: bytes) -> str:
    """Append one audit entry and return its leaf hash. Not yet implemented."""
    raise NotImplementedError("ledger.interface lands in phase 9")
