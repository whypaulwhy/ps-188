"""Metric definitions used by the runner: detection rates, calibration and per-rung breakdowns."""

from __future__ import annotations


def compute_metrics(predictions: object, truth: object) -> object:
    """Compute the evaluation metric set for one run. Not yet implemented."""
    raise NotImplementedError("eval.metrics lands in phase 6")
