"""Verhoeff checksum used by UIDAI for the twelfth digit of an Aadhaar number."""

from __future__ import annotations


def verhoeff_is_valid(digits: str) -> bool:
    """Return whether a digit string carries a valid Verhoeff checksum. Not yet implemented."""
    raise NotImplementedError("core.standards.verhoeff lands in phase 2")
