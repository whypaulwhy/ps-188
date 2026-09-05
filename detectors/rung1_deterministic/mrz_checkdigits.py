"""Rung 1 detector: recompute every ICAO 9303 MRZ check digit and compare with the printed one."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the MRZ check-digit detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung1_deterministic.mrz_checkdigits lands in phase 5")
