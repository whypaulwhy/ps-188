"""Rung 2 detector: TruFor tamper localisation, the only module permitted to import PyTorch."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the TruFor tamper localisation detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung2_inference.tamper_trufor lands in phase 6")
