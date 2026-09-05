"""Forgery type: the document is printed and rephotographed, or replayed from a screen."""

from __future__ import annotations

from datagen.forgeries.base import Forgery


class Recapture(Forgery):
    """Simulate a print-and-scan or screen-replay capture chain. Not yet implemented."""
