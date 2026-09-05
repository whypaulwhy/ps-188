"""Rung 2 detector: PDF object, incremental-update and producer anomalies.

Everything short of the signature check, which is Rung 0.
"""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the PDF structural anomaly detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung2_inference.pdf_structure lands in phase 6")
