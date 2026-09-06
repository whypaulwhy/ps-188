"""Forgery type: the portrait is replaced with a different one.

The commonest alteration to a genuine document, and the one a signed
document defeats outright: an Aadhaar Secure QR covers the photograph, so any
substitution invalidates the signature. On a document with no signature,
nothing below Rung 2 sees this at all.
"""

from __future__ import annotations

import random

from PIL import ImageDraw

from datagen.forgeries.base import Forgery
from datagen.synthetic_docs import Specimen


class PhotoSubstitution(Forgery):
    """Replace the document portrait with a different one."""

    name = "photo_substitution"
    alters = "the portrait region, leaving every printed field and the strip untouched"

    def apply(self, specimen: Specimen, *, seed: int) -> bytes:
        """Paint a different portrait into the portrait box."""
        rng = random.Random(seed)
        image = self._open(specimen)
        draw = ImageDraw.Draw(image)
        draw.rectangle(
            specimen.portrait_box,
            fill=(rng.randrange(90, 140), rng.randrange(90, 140), rng.randrange(110, 160)),
            outline=(120, 120, 126),
        )
        return self._encode(image)
