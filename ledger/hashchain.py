"""Append-only Merkle hash chain with Ed25519 signed checkpoints; the default ledger backend."""

from __future__ import annotations


def build_merkle_root(leaves: list[bytes]) -> bytes:
    """Return the Merkle root over an ordered list of leaf hashes. Not yet implemented."""
    raise NotImplementedError("ledger.hashchain lands in phase 9")
