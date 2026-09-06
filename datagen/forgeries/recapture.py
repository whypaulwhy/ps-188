"""Forgery type: the document is printed and rephotographed, or replayed.

Not an alteration of content at all, which is what makes it interesting: every
field is correct and every check digit agrees. What differs is the capture
chain, and that is a Rung 2 question about pixels rather than a Rung 1 question
about values.
"""

from __future__ import annotations

import io
import random

from PIL import Image, ImageFilter

from datagen.forgeries.base import Forgery
from datagen.synthetic_docs import Specimen


class Recapture(Forgery):
    """Simulate a print-and-scan or screen-replay capture chain."""

    name = "recapture"
    alters = "nothing on the document; only the capture chain, which stays lossy and skewed"

    def apply(self, specimen: Specimen, *, seed: int) -> bytes:
        """Blur, rotate slightly, and round-trip through lossy compression."""
        rng = random.Random(seed)
        image = self._open(specimen)
        image = image.rotate(
            rng.uniform(-1.2, 1.2), resample=Image.BICUBIC, fillcolor=(238, 236, 228)
        )
        image = image.filter(ImageFilter.GaussianBlur(radius=0.8))
        lossy = io.BytesIO()
        image.save(lossy, format="JPEG", quality=rng.randrange(55, 75))
        lossy.seek(0)
        return self._encode(Image.open(lossy).convert("RGB"))
