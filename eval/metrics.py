"""What an evaluation measures, and what it refuses to collapse into one figure.

Three rates per detector, **per class of document**, never averaged together:

* **escalation rate** — how often the detector said `SUSPICIOUS`. On forged
  documents that is detection. On genuine documents it is the false-escalation
  rate, and it is the number that decides whether an officer can work.
* **abstention rate** — how often it said `INCONCLUSIVE`. Reported on its own
  and never folded into an error rate. A detector that abstains half the time
  may still be useful, but the abstention has to be visible.
* **score distribution** — the quartiles of the suspicion score. This is what
  makes a threshold choosable on evidence instead of guessed at, and it is why
  the raw numbers are reported rather than only the pass/fail counts.

There is deliberately no single headline figure. Averaging detection across
forgery types hides which attacks a detector is blind to, and averaging across
genuine and forged documents produces a number that sounds like accuracy and
means nothing.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass

from core.contracts import Result


@dataclass(frozen=True)
class Outcome:
    """What one detector said about one document."""

    detector_id: str
    document_class: str
    """`genuine`, or the name of the forgery generator that produced it."""

    result: Result
    score: float | None


@dataclass(frozen=True)
class Rates:
    """How one detector behaved on one class of document."""

    detector_id: str
    document_class: str
    count: int
    escalated: int
    abstained: int
    scores: tuple[float, ...]

    @property
    def escalation_rate(self) -> float:
        """Fraction of documents in this class the detector escalated."""
        return self.escalated / self.count if self.count else 0.0

    @property
    def abstention_rate(self) -> float:
        """Fraction of documents in this class the detector could not judge."""
        return self.abstained / self.count if self.count else 0.0

    @property
    def quartiles(self) -> tuple[float, float, float] | None:
        """Return the lower quartile, median and upper quartile of the scores.

        Returns:
            The three values, or None when too few scores exist to compute
            them. Reported so that a threshold can be chosen from evidence.
        """
        if len(self.scores) < 4:
            return None
        ordered = sorted(self.scores)
        return (
            statistics.quantiles(ordered, n=4)[0],
            statistics.median(ordered),
            statistics.quantiles(ordered, n=4)[2],
        )


def summarise(outcomes: Sequence[Outcome]) -> list[Rates]:
    """Group outcomes into per-detector, per-class rates.

    Args:
        outcomes: Every observation from one evaluation run.

    Returns:
        One `Rates` per detector and document class, ordered by detector then
        class, with `genuine` first within each detector so that the
        false-escalation rate is the first thing a reader sees.
    """
    grouped: dict[tuple[str, str], list[Outcome]] = {}
    for outcome in outcomes:
        grouped.setdefault((outcome.detector_id, outcome.document_class), []).append(outcome)

    rates = [
        Rates(
            detector_id=detector_id,
            document_class=document_class,
            count=len(items),
            escalated=sum(1 for item in items if item.result is Result.SUSPICIOUS),
            abstained=sum(1 for item in items if item.result is Result.INCONCLUSIVE),
            scores=tuple(item.score for item in items if item.score is not None),
        )
        for (detector_id, document_class), items in grouped.items()
    ]
    return sorted(
        rates, key=lambda r: (r.detector_id, r.document_class != "genuine", r.document_class)
    )


def separation(rates: Sequence[Rates], detector_id: str) -> dict[str, float]:
    """Return how far each forgery class scores above genuine, class by class.

    Reported per class and never pooled. An earlier version of this function
    took one median across every forgery type together, and it hid the only
    real result in the run: a detector that separates one attack cleanly and is
    blind to four others averages out to looking useless, which is the same
    error as averaging detection into a single headline figure.

    Args:
        rates: The summarised run.
        detector_id: The detector to examine.

    Returns:
        Forgery class to median score gap. Empty when the detector produced no
        scores at all. Zero or below means that attack is invisible to it.
    """
    for_detector = [rate for rate in rates if rate.detector_id == detector_id]
    genuine = [
        score for rate in for_detector if rate.document_class == "genuine" for score in rate.scores
    ]
    if not genuine:
        return {}
    baseline = statistics.median(genuine)
    return {
        rate.document_class: statistics.median(rate.scores) - baseline
        for rate in for_detector
        if rate.document_class != "genuine" and rate.scores
    }
