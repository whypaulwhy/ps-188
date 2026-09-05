"""Parse ICAO Doc 9303 machine readable zones (TD1, TD2, TD3, MRV-A, MRV-B) into fields."""

from __future__ import annotations

from collections.abc import Sequence


def parse_mrz(lines: Sequence[str]) -> object:
    """Split raw MRZ lines into their fixed-offset fields. Not yet implemented."""
    raise NotImplementedError("core.standards.mrz.parse lands in phase 2")
