"""Rung 3 advisory: has this document been presented here before?

**It decides nothing.** Rung 3 is advisory to the officer and the trust ladder
never consults it. A repeat crossing is ordinary on these borders, where the
same people cross daily, so this is context rather than suspicion and the
wording says so.

**It links documents, not people.** A crossing is matched on the salted digest
of the document number. Someone presenting a second document is a second
history. That boundary is deliberate: linking a person across documents needs
biometrics, which would turn a document log into a movement history of a border
population and is a different system requiring its own review. See
``docs/threat-model.md``.

**An unreadable document is reported as unchecked, not as unremarkable.** If the
number cannot be recovered there is no history to look up, and reporting
``NO_FLAG`` would tell an officer the history was clean when it was never
consulted.
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from core.privacy import DeploymentKey
from detectors.base import Detector, register
from detectors.rung3_context._identify import document_digest
from detectors.rung3_context.context_store import CrossingHistory

DETECTOR_VERSION: Final[str] = "repeat_identity/1.0.0"

NOT_IDENTIFIED: Final[str] = (
    "This document could not be identified from its coded strip, so no check was "
    "made for previous crossings. Nothing is known either way."
)
NO_HISTORY: Final[str] = (
    "This checkpoint holds no record of previous crossings, so none was consulted."
)


@register
class RepeatIdentityDetector(Detector):
    """Reports whether the same document has been presented before."""

    id = "rung3.repeat_identity"
    rung = Rung.CONTEXTUAL

    def __init__(self, history: CrossingHistory, *, key: DeploymentKey) -> None:
        """Hold the crossing history and the key that digests match under.

        Args:
            history: Previous sightings, supplied by the caller. A detector
                never reaches for storage itself.
            key: The deployment key, so a digest computed here matches one
                computed when the earlier crossing was recorded.
        """
        self._history = history
        self._key = key

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should."""
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Look for earlier sightings of this document."""
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
        if not len(self._history):
            return Result.NOT_CHECKED, (NO_HISTORY,)

        digest = document_digest(subject, key=self._key)
        if digest is None:
            return Result.NOT_CHECKED, (NOT_IDENTIFIED,)

        sightings = self._history.sightings(digest, before=subject.provenance.captured_at)
        if not sightings:
            return Result.NO_FLAG, (
                "This document has not been presented at this checkpoint before, as "
                "far as its records go.",
            )

        latest = sightings[-1]
        where = {crossing.checkpoint_id for crossing in sightings}
        seen_on = latest.seen_at.strftime("%d %B %Y")
        return Result.FLAG_RAISED, (
            f"This document has been presented {len(sightings)} time(s) before, most "
            f"recently on {seen_on} at {latest.checkpoint_id}.",
            f"Seen at {len(where)} crossing point(s). Frequent crossing is ordinary "
            f"here and is not by itself a reason for concern.",
        )


def build(history: CrossingHistory, *, key: DeploymentKey) -> Detector:
    """Construct the repeat identity advisory detector."""
    return RepeatIdentityDetector(history, key=key)
