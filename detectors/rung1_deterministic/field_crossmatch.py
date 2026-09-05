"""Rung 1 detector: cross-check MRZ fields against the printed visual inspection zone."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the MRZ-versus-VIZ cross-consistency detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung1_deterministic.field_crossmatch lands in phase 5")
