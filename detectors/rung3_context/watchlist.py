"""Rung 3 advisory: is this document on an operator-supplied watchlist?

**It decides nothing.** A watchlist hit is information for the officer. The
trust ladder never consults Rung 3, so a hit cannot reject a document and a
miss cannot clear one.

**It matches on exact digest only**, and that is a decision rather than an
omission. Name matching catches aliases, and it also flags an innocent person
who shares a name with someone listed. On a border where the same people cross
every morning, that advisory would appear in front of an officer daily,
indefinitely, with no mechanism to clear it. An exact match on a document number
has no false positives at all. It misses more, and what it reports is true.

**No list is reported as no check.** A checkpoint that was never given a
watchlist says so, rather than reporting that the traveller is not on one.
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from core.privacy import DeploymentKey
from detectors.base import Detector, register
from detectors.rung3_context._identify import document_digest
from detectors.rung3_context.context_store import Watchlist

DETECTOR_VERSION: Final[str] = "watchlist/1.0.0"

NO_LIST: Final[str] = (
    "This checkpoint holds no watchlist, so none was consulted. Nothing is known either way."
)
NOT_IDENTIFIED: Final[str] = (
    "This document could not be identified from its coded strip, so no watchlist "
    "was consulted. Nothing is known either way."
)


@register
class WatchlistDetector(Detector):
    """Reports whether the presented document is on the operator's watchlist."""

    id = "rung3.watchlist"
    rung = Rung.CONTEXTUAL

    def __init__(self, watchlist: Watchlist, *, key: DeploymentKey) -> None:
        """Hold the watchlist and the key its digests were computed under.

        Args:
            watchlist: The operator's list, supplied by the caller and holding
                digests rather than numbers.
            key: The deployment key.
        """
        self._watchlist = watchlist
        self._key = key

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should."""
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Consult the watchlist, or say why it could not be consulted."""
        started = time.perf_counter()
        result, reasons = self._examine(subject)
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                reasons=reasons,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )

    def _examine(self, subject: Subject) -> tuple[Result, tuple[str, ...]]:
        """Decide the flag and the officer-facing wording."""
        if not len(self._watchlist):
            return Result.NOT_CHECKED, (NO_LIST,)

        digest = document_digest(subject, key=self._key)
        if digest is None:
            return Result.NOT_CHECKED, (NOT_IDENTIFIED,)

        entry = self._watchlist.entry(digest)
        if entry is None:
            return Result.NO_FLAG, (
                "This document is not on the watchlist held at this checkpoint.",
            )
        return Result.FLAG_RAISED, (
            "This document is on the watchlist held at this checkpoint.",
            entry.reason,
        )


def build(watchlist: Watchlist, *, key: DeploymentKey) -> Detector:
    """Construct the watchlist advisory detector."""
    return WatchlistDetector(watchlist, key=key)
