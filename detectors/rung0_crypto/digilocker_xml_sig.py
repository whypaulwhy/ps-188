"""Rung 0 detector: verify the XML digital signature on a DigiLocker issued document."""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the DigiLocker XML signature detector. Not yet implemented."""
    raise NotImplementedError("detectors.rung0_crypto.digilocker_xml_sig lands in phase 4")
