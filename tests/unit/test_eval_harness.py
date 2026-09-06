"""The evaluation harness: what it measures and what it refuses to average.

Rule 2 of CLAUDE.md makes this the only place a performance number may come
from, which makes the harness itself worth testing. In particular it must not
quietly collapse per-class results into one figure, because that is exactly the
number somebody would put on a slide.
"""

from __future__ import annotations

import pytest

from core.contracts import Result
from eval.metrics import Outcome, Rates, separation, summarise
from eval.protocol import PROTOCOLS, load_protocol


def outcome(document_class: str, result: Result, score: float | None) -> Outcome:
    """Build one observation."""
    return Outcome("d.one", document_class, result, score)


def test_a_protocol_names_a_real_dataset() -> None:
    """A typo must fail rather than silently measure something else."""
    assert load_protocol("synthetic-utopia-v1").seed
    with pytest.raises(KeyError):
        load_protocol("no-such-dataset")


def test_every_protocol_is_reproducible() -> None:
    """A seed and a size, or a report cannot be replayed."""
    for protocol in PROTOCOLS.values():
        assert protocol.seed
        assert protocol.genuine_count > 0
        assert protocol.forgeries
        assert protocol.description.strip()


def test_rates_are_grouped_per_detector_and_per_class() -> None:
    """Never pooled: pooling hides which attacks a detector is blind to."""
    rates = summarise(
        [
            outcome("genuine", Result.NO_FINDING, 0.1),
            outcome("genuine", Result.SUSPICIOUS, 0.9),
            outcome("recapture", Result.SUSPICIOUS, 0.8),
        ]
    )

    assert {rate.document_class for rate in rates} == {"genuine", "recapture"}
    assert next(r for r in rates if r.document_class == "genuine").escalation_rate == 0.5


def test_genuine_is_reported_first() -> None:
    """The false-escalation rate is the number that decides whether an officer can work."""
    rates = summarise(
        [outcome("recapture", Result.SUSPICIOUS, 0.8), outcome("genuine", Result.NO_FINDING, 0.1)]
    )

    assert rates[0].document_class == "genuine"


def test_abstention_is_counted_separately_from_escalation() -> None:
    """A detector that abstains has not found anything, and must not look as if it did."""
    rates = summarise([outcome("genuine", Result.INCONCLUSIVE, None)])

    assert rates[0].abstention_rate == 1.0
    assert rates[0].escalation_rate == 0.0
    assert rates[0].scores == ()


def test_quartiles_need_enough_scores_to_mean_anything() -> None:
    """Three numbers do not have quartiles, and pretending otherwise invents precision."""
    assert Rates("d", "genuine", 3, 0, 0, (0.1, 0.2, 0.3)).quartiles is None
    assert Rates("d", "genuine", 4, 0, 0, (0.1, 0.2, 0.3, 0.4)).quartiles is not None


def test_separation_is_reported_per_forgery_class() -> None:
    """A detector that catches one attack and misses four must not average out to useless.

    An earlier version pooled every forgery type into a single median, which
    reported +0.03 for a detector that in fact separated one attack by +0.32
    and was blind to the rest.
    """
    rates = summarise(
        [
            outcome("genuine", Result.NO_FINDING, 0.3),
            outcome("recapture", Result.SUSPICIOUS, 0.9),
            outcome("copy_move", Result.NO_FINDING, 0.3),
        ]
    )

    gaps = separation(rates, "d.one")

    assert gaps == {"recapture": pytest.approx(0.6), "copy_move": pytest.approx(0.0)}


def test_separation_is_empty_when_a_detector_produced_no_scores() -> None:
    """An abstaining detector has nothing to separate, and says so rather than showing zero."""
    rates = summarise([outcome("genuine", Result.INCONCLUSIVE, None)])

    assert separation(rates, "d.one") == {}
