"""Rung 0 detector: verify PKCS#7 signatures embedded in a signed PDF document."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the signed-PDF PKCS#7 detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung0_crypto.pdf_pkcs7 lands in phase 4")
