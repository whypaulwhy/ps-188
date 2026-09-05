"""Aggregation of multiple Rung 2 scores into a single escalation signal."""

from __future__ import annotations

from collections.abc import Sequence

from core.contracts import Evidence


def aggregate_inference_scores(evidence: Sequence[Evidence]) -> float:
    """Combine Rung 2 suspicion scores into one calibrated figure. Not yet implemented."""
    raise NotImplementedError("core.trust.aggregation lands in phase 6")
