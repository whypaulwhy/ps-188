"""Forgery type: a printed field is altered, leaving the coded strip alone.

This is what a cross-check between the printed page and the machine-readable
strip exists to catch, and it is the reason that check matters: the strip stays
internally consistent, so check-digit arithmetic passes and the document looks
correct to anything that reads only the strip.
"""

from __future__ import annotations

from PIL import ImageDraw, ImageFont

from datagen.forgeries.base import Forgery
from datagen.synthetic_docs import Specimen


class TextFieldEdit(Forgery):
    """Alter one printed field in place, without touching the strip."""

    name = "text_field_edit"
    alters = "one printed field, leaving the machine-readable strip consistent and unchanged"

    def apply(self, specimen: Specimen, *, seed: int) -> bytes:
        """Overwrite the printed date of birth with a different value."""
        image = self._open(specimen)
        draw = ImageDraw.Draw(image)
        row = list(specimen.fields).index("date_of_birth")
        top = (100 + row * 44 + 18) * 2
        box = (320 * 2, top - 4, 700 * 2, top + 52)
        draw.rectangle(box, fill=(250, 249, 245))
        original = specimen.fields["date_of_birth"]
        altered = original[:4] + ("02" if original[4:] != "02" else "03")
        draw.text((320 * 2, top), altered, font=ImageFont.load_default(size=44), fill=(18, 18, 22))
        return self._encode(image)
