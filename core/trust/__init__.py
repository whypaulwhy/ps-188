"""The trust ladder: how evidence from different rungs resolves into one verdict.

The rules live in :mod:`core.trust.policy` as data and are applied by
:func:`core.trust.ladder.resolve`. Nothing in this package performs I/O.
"""

from __future__ import annotations

from core.trust.ladder import resolve
from core.trust.policy import POLICY_VERSION, decision_severity

__all__ = ["POLICY_VERSION", "decision_severity", "resolve"]
