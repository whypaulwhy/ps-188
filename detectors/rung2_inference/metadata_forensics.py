"""Rung 2 detector: EXIF, XMP and software-fingerprint inconsistencies in a captured image."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the image metadata forensics detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung2_inference.metadata_forensics lands in phase 6")
