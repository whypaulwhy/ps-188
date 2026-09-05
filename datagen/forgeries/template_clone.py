"""Forgery type: a fabricated document built from a cloned issuer template with invented data."""

from __future__ import annotations

from datagen.forgeries.base import Forgery


class TemplateClone(Forgery):
    """Fabricate a whole document from a cloned template. Not yet implemented."""
