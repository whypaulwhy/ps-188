"""Deterministic template renderer turning a Verdict into officer-facing text; no model involved."""

from __future__ import annotations

from core.contracts import Verdict


def render_verdict(verdict: Verdict) -> str:
    """Render a Verdict as officer-facing text, what was not checked included.

    Not yet implemented.
    """
    raise NotImplementedError("explain.renderer lands in phase 9")
