"""Document date arithmetic: expiry, issue-before-expiry, date-of-birth plausibility."""

from __future__ import annotations

import datetime


def is_expired(expiry: datetime.date, *, on: datetime.date) -> bool:
    """Return whether a document is expired on a given date. Not yet implemented."""
    raise NotImplementedError("core.standards.date_rules lands in phase 2")
