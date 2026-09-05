"""Rung 0 detector: ePassport passive authentication over the SOD.

Inert until chip reader hardware exists at the checkpoint.
"""

from __future__ import annotations

from detectors.base import Detector


def build() -> Detector:
    """Construct the ePassport passive authentication detector. Blocked on reader hardware."""
    raise NotImplementedError(
        "detectors.rung0_crypto.epassport_sod is blocked on chip reader hardware"
    )
