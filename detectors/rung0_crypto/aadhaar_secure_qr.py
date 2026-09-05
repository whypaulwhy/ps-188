"""Rung 0 detector: verify the UIDAI Secure QR signature on an Aadhaar document."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the Aadhaar Secure QR signature detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung0_crypto.aadhaar_secure_qr lands in phase 4")
