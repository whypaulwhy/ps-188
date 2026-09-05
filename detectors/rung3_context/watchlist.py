"""Rung 3 advisory: match against an operator-supplied watchlist; never decides, only flags."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the watchlist advisory detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung3_context.watchlist lands in phase 8")
