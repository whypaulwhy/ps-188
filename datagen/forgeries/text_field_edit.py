"""Forgery type: a printed field such as date of birth or name is digitally altered."""

from __future__ import annotations

from datagen.forgeries.base import Forgery


class TextFieldEdit(Forgery):
    """Alter one printed text field in place. Not yet implemented."""
