"""Every check in the system. Each one returns Evidence and declares a trust rung.

Detectors are grouped by rung so that the rung of any check is visible from its
import path. Nothing in this package may import from ``api``, ``db`` or ``ui``;
anything a detector needs is passed to it as an argument.
"""

from __future__ import annotations

from detectors.base import Detector, clear_registry, get, register, registered

__all__ = ["Detector", "clear_registry", "get", "register", "registered"]
