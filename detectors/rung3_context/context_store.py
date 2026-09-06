"""The context a Rung 3 detector is given: prior crossings, and a watchlist.

Both are built by the caller and handed to the detector. Rule 5 requires it,
and it also means a detector cannot widen its own view of a traveller.

**Everything here is keyed on salted digests, never on document numbers.** A
watchlist arrives from an operator as a list of numbers; it is hashed on load
and the raw entries are not retained. A crossing history records that *a
document* was seen, not who presented it. Rule 3 applies here as much as
anywhere: no raw identifier is stored, and there is nothing in either structure
that can be read back into a number without the deployment key.

**What a crossing history is, stated plainly.** It is a record of which
documents crossed where and when. `docs/threat-model.md` names it for what it
is: building one means holding a movement history of a border population, and
it is the most privacy-invasive thing this project does. Two boundaries keep it
narrow, and both are deliberate:

* it links **documents, not people** — the same person with a second document
  is a second history, and linking them would require biometrics, which is a
  different system needing its own review;
* it holds digests and timestamps, so a stolen history without the key says
  that *something* crossed, not what.

Retention is not this module's to enforce -- a history is supplied, not owned --
but records fall under the `CASE_RECORD` window, which a `RetentionPolicy`
cannot omit.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from core.privacy import DeploymentKey, IdentifierKind, RawIdentifier, hash_document_number

DIGEST_LENGTH: Final[int] = 64


@dataclass(frozen=True)
class Crossing:
    """One previous sighting of one document."""

    digest: str
    """Salted digest of the document number. Never the number."""

    seen_at: datetime.datetime
    """When the document was presented. Must carry a timezone."""

    checkpoint_id: str
    """Where it was presented."""

    def __post_init__(self) -> None:
        """Reject a record that cannot be placed on a timeline or read back.

        Raises:
            ValueError: If the digest is the wrong length or the timestamp is
                naive.
        """
        if len(self.digest) != DIGEST_LENGTH:
            msg = "a crossing must be keyed on a full digest, never on a document number"
            raise ValueError(msg)
        if self.seen_at.tzinfo is None or self.seen_at.tzinfo.utcoffset(self.seen_at) is None:
            msg = "seen_at must be timezone aware"
            raise ValueError(msg)


@dataclass(frozen=True)
class WatchlistEntry:
    """One watchlist record, and why it is on the list."""

    digest: str
    """Salted digest of the document number."""

    reason: str
    """Officer-facing, and shown verbatim. Written for a person, not a case file."""


class CrossingHistory:
    """Previous sightings, supplied by the caller.

    Empty is a legitimate and common state: a checkpoint with no history
    reports that it could not check rather than that nothing was found.
    """

    __slots__ = ("_by_digest",)

    def __init__(self, crossings: Sequence[Crossing] = ()) -> None:
        """Index the supplied crossings by digest."""
        indexed: dict[str, list[Crossing]] = {}
        for crossing in crossings:
            indexed.setdefault(crossing.digest, []).append(crossing)
        self._by_digest = {
            digest: tuple(sorted(items, key=lambda item: item.seen_at))
            for digest, items in indexed.items()
        }

    def sightings(self, digest: str, *, before: datetime.datetime) -> tuple[Crossing, ...]:
        """Return earlier sightings of one document.

        Args:
            digest: The document's salted digest.
            before: The current crossing's capture time. Sightings at or after
                it are excluded, so a case never counts itself as its own
                history and a replay reaches the same answer.

        Returns:
            The earlier sightings, oldest first.
        """
        return tuple(
            crossing for crossing in self._by_digest.get(digest, ()) if crossing.seen_at < before
        )

    def __len__(self) -> int:
        """Return how many distinct documents this history knows about."""
        return len(self._by_digest)


class Watchlist:
    """Documents an operator has flagged, supplied by the caller.

    Empty means this checkpoint has no list, which a detector reports as a
    check it could not make.
    """

    __slots__ = ("_by_digest",)

    def __init__(self, entries: Sequence[WatchlistEntry] = ()) -> None:
        """Index the supplied entries by digest.

        Raises:
            ValueError: If two entries claim the same digest, which would make
                the reason shown to an officer arbitrary.
        """
        digests = [entry.digest for entry in entries]
        if len(digests) != len(set(digests)):
            msg = "two watchlist entries cannot share a digest"
            raise ValueError(msg)
        self._by_digest = {entry.digest: entry for entry in entries}

    @classmethod
    def from_numbers(
        cls,
        numbers: Iterable[tuple[str, str]],
        *,
        key: DeploymentKey,
        kind: IdentifierKind = IdentifierKind.PASSPORT,
    ) -> Watchlist:
        """Build a watchlist from raw document numbers, hashing them on the way in.

        The raw numbers exist only for the duration of this call. Nothing here
        retains them, and the resulting list holds digests only.

        Args:
            numbers: Pairs of document number and the officer-facing reason it
                is listed.
            key: The deployment key, so digests match those computed at a
                crossing.
            kind: Which kind of document number these are. Digests are domain
                separated by kind, so this has to match.

        Returns:
            The watchlist.
        """
        return cls(
            [
                WatchlistEntry(
                    digest=hash_document_number(RawIdentifier(number, kind=kind), key=key),
                    reason=reason,
                )
                for number, reason in numbers
            ]
        )

    def entry(self, digest: str) -> WatchlistEntry | None:
        """Return the entry for a digest, or None if it is not listed."""
        return self._by_digest.get(digest)

    def __len__(self) -> int:
        """Return how many documents are listed."""
        return len(self._by_digest)

    def __iter__(self) -> Iterator[WatchlistEntry]:
        """Iterate the entries."""
        return iter(self._by_digest.values())
