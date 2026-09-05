"""Retention windows and deletion eligibility for biometrics, crops and case records."""

from __future__ import annotations

import datetime


def deletion_due_at(created_at: datetime.datetime, *, category: str) -> datetime.datetime:
    """Return the instant at which a stored artefact must be destroyed. Not yet implemented."""
    raise NotImplementedError("core.privacy.retention lands in phase 3")
