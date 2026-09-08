"""What goes into the transparency log, and what comes back out.

**A log entry is a digest of a verdict, not the verdict.** That is the decision
this module exists to enforce, and the reason is that the two requirements on
this log pull against each other: it must be append-only to be worth anything,
and the retention policy requires case records to be destroyed on schedule. A
log holding verdicts could not honour the second without breaking the first,
because deleting a leaf destroys the Merkle chain for every entry after it.

Holding a digest resolves it. The log is permanent and genuinely append-only.
The verdict lives in the case record under its retention window. While the
record survives you can replay it and check it against the log; once retention
destroys it you can still prove **that** a decision was made at a time and has
not been altered, but not what it said.

That is a real limit on "a decision can be replayed from the ledger", and
stating it is better than a log that quietly makes retention unenforceable.

**One field is excluded from the digest.** `runtime_ms` records how long a
detector took, which differs on every run and is not part of the decision.
Committing to it would mean a faithful replay never matched its own log entry.
`model_version` is **not** excluded: a different model is a different basis for
the decision, and the log should say so.

**An officer's review is a second entry, never an edit of the first.** The log
holds what happened to a case in order: what the system decided, and then what
a person decided about it. Overwriting the first with the second is precisely
the tamper this log exists to detect.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel

from core.contracts import DestructionRecord, OfficerReview, Verdict
from ledger.hashchain import (
    Checkpoint,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    sign_checkpoint,
)

VOLATILE_FIELDS: Final[frozenset[str]] = frozenset({"runtime_ms"})
"""Excluded from the digest. See the module docstring for why only this one."""


@dataclass(frozen=True)
class LedgerEntry:
    """One recorded decision: which case, what it hashed to, and when."""

    case_id: str
    verdict_digest: str
    recorded_at: datetime.datetime

    def canonical_bytes(self) -> bytes:
        """Return the bytes hashed into the log."""
        return b"sentinelid-entry-v1|%s|%s|%s" % (
            self.case_id.encode(),
            self.verdict_digest.encode(),
            self.recorded_at.isoformat().encode(),
        )


def _strip_volatile(value: Any) -> Any:  # noqa: ANN401 - arbitrary decoded JSON
    """Remove fields that differ between two faithful runs of the same case."""
    if isinstance(value, dict):
        return {
            key: _strip_volatile(nested)
            for key, nested in sorted(value.items())
            if key not in VOLATILE_FIELDS
        }
    if isinstance(value, list):
        return [_strip_volatile(item) for item in value]
    return value


def _canonical_bytes(record: BaseModel) -> bytes:
    """Return the stable serialisation any audit record is digested from."""
    decoded = json.loads(record.model_dump_json())
    return json.dumps(_strip_volatile(decoded), sort_keys=True, separators=(",", ":")).encode()


def canonical_verdict_bytes(verdict: Verdict) -> bytes:
    """Return the stable serialisation a verdict is digested from.

    Keys are sorted and volatile fields removed, so that replaying a case
    produces the same bytes as the original run. Without both, a replay would
    disagree with its own log entry for reasons that have nothing to do with
    the decision.

    Args:
        verdict: The decision to serialise.

    Returns:
        Canonical JSON bytes.
    """
    return _canonical_bytes(verdict)


def canonical_destruction_bytes(destruction: DestructionRecord) -> bytes:
    """Return the stable serialisation a destruction record is digested from.

    A destruction carries no volatile field, so nothing is stripped from it in
    practice. It goes through the same function as a verdict and a review
    because the log has to treat every kind of record identically; a second
    canonical form is one more thing that can drift.

    Args:
        destruction: The destruction to serialise.

    Returns:
        Canonical JSON bytes.
    """
    return _canonical_bytes(destruction)


def canonical_review_bytes(review: OfficerReview) -> bytes:
    """Return the stable serialisation an officer review is digested from.

    A review carries no volatile field, so nothing is stripped from it in
    practice. It goes through the same function anyway: two canonical forms
    that could drift apart is one more thing to get wrong, and the log has to
    treat both kinds of record identically.

    Args:
        review: The officer's decision.

    Returns:
        Canonical JSON bytes.
    """
    return _canonical_bytes(review)


class TransparencyLog:
    """An in-memory append-only log with signed checkpoints.

    Storage is deliberately not this class's concern: it holds leaves and
    answers questions about them, and a caller persists what it needs. That
    keeps the Merkle arithmetic testable without a database, and it is why the
    interface is small enough to reimplement over any backend.
    """

    __slots__ = ("_entries", "_leaves")

    def __init__(self, entries: list[LedgerEntry] | None = None) -> None:
        """Rebuild a log from its entries, in order."""
        self._entries: list[LedgerEntry] = []
        self._leaves: list[bytes] = []
        for entry in entries or []:
            self.append(entry)

    def append(self, entry: LedgerEntry) -> int:
        """Add one entry to the end of the log.

        Args:
            entry: The record to append.

        Returns:
            Its index. Indices are never reused, because nothing is removed.
        """
        self._entries.append(entry)
        self._leaves.append(leaf_hash(entry.canonical_bytes()))
        return len(self._leaves) - 1

    def record(self, verdict: Verdict, *, case_id: str, recorded_at: datetime.datetime) -> int:
        """Record a decision, digesting the verdict rather than storing it.

        Args:
            verdict: The decision made.
            case_id: Which case it belongs to.
            recorded_at: When it was recorded.

        Returns:
            The index of the new entry.
        """
        digest = leaf_hash(canonical_verdict_bytes(verdict)).hex()
        return self.append(LedgerEntry(case_id, digest, recorded_at))

    def record_review(self, review: OfficerReview) -> int:
        """Record an officer's decision as its own entry.

        A review never replaces the verdict's entry. It is appended after it, so
        the log holds the sequence of what happened to a case rather than only
        its latest state.

        Args:
            review: The officer's decision.

        Returns:
            The index of the new entry.
        """
        digest = leaf_hash(canonical_review_bytes(review)).hex()
        return self.append(LedgerEntry(review.case_id, digest, review.recorded_at))

    def record_destruction(self, destruction: DestructionRecord) -> int:
        """Record a lawful destruction as its own entry.

        The entry for the decision that was destroyed stays exactly where it is.
        Removing it would break the Merkle chain for everything appended after
        it, which is the one failure this log cannot recover from. So a
        destruction is an append like any other, and the log reads as the
        sequence of what happened to a case: decided, reviewed, destroyed.

        Args:
            destruction: What was destroyed, and under which policy.

        Returns:
            The index of the new entry.
        """
        digest = leaf_hash(canonical_destruction_bytes(destruction)).hex()
        return self.append(LedgerEntry(destruction.case_id, digest, destruction.destroyed_at))

    def matches_destruction(self, destruction: DestructionRecord, *, index: int) -> bool:
        """Report whether a destruction digests to what was logged at an index.

        Args:
            destruction: The destruction to check.
            index: The entry to compare against.

        Returns:
            Whether the digests agree.
        """
        if not 0 <= index < len(self._entries):
            return False
        digest = leaf_hash(canonical_destruction_bytes(destruction)).hex()
        return self._entries[index].verdict_digest == digest

    def matches_review(self, review: OfficerReview, *, index: int) -> bool:
        """Report whether a review digests to what was logged at an index.

        Args:
            review: The review to check.
            index: The entry to compare against.

        Returns:
            Whether the digests agree.
        """
        if not 0 <= index < len(self._entries):
            return False
        digest = leaf_hash(canonical_review_bytes(review)).hex()
        return self._entries[index].verdict_digest == digest

    def matches(self, verdict: Verdict, *, index: int) -> bool:
        """Report whether a verdict digests to what was logged at an index.

        This is the replay check: run a case again, and ask the log whether the
        result is the one it recorded.

        Args:
            verdict: The replayed decision.
            index: The entry to compare against.

        Returns:
            Whether the digests agree.
        """
        if not 0 <= index < len(self._entries):
            return False
        return (
            self._entries[index].verdict_digest == leaf_hash(canonical_verdict_bytes(verdict)).hex()
        )

    def root(self) -> bytes:
        """Return the current Merkle root."""
        return merkle_root(self._leaves)

    def proof(self, index: int) -> tuple[bytes, ...]:
        """Return an inclusion proof for one entry."""
        return inclusion_proof(self._leaves, index)

    def leaf(self, index: int) -> bytes:
        """Return the leaf hash at an index."""
        return self._leaves[index]

    def checkpoint(self, *, key: Any, signed_at: datetime.datetime) -> Checkpoint:  # noqa: ANN401
        """Sign a statement about the log's current state.

        Args:
            key: The log's Ed25519 signing key.
            signed_at: When the checkpoint is made.

        Returns:
            The signed checkpoint, for publication outside this deployment.
        """
        return sign_checkpoint(
            tree_size=len(self._leaves), root=self.root(), signed_at=signed_at, key=key
        )

    def entries(self) -> tuple[LedgerEntry, ...]:
        """Return every entry, in order."""
        return tuple(self._entries)

    def __len__(self) -> int:
        """Return how many entries the log holds."""
        return len(self._leaves)


def append_entry(payload: bytes) -> str:
    """Append one audit entry and return its leaf hash.

    Retained as the narrow backend-agnostic entry point named in the roadmap.
    A real deployment uses :class:`TransparencyLog` and persists its entries.

    Args:
        payload: The canonical bytes of the entry.

    Returns:
        The leaf hash, hex encoded.
    """
    return leaf_hash(payload).hex()
