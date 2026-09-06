"""Forgery type: a region is cloned over another to hide or duplicate content.

Leaves no seam a human eye finds quickly, and no arithmetic notices it at all.
Only Rung 2 has any chance here, and Rung 2 can only escalate.
"""

from __future__ import annotations

from datagen.forgeries.base import Forgery
from datagen.synthetic_docs import Specimen


class CopyMove(Forgery):
    """Clone one region of the document over another."""

    name = "copy_move"
    alters = "a region of the document, duplicated from elsewhere on the same document"

    def apply(self, specimen: Specimen, *, seed: int) -> bytes:
        """Copy a patch of the printed area over a neighbouring patch."""
        image = self._open(specimen)
        source = (640, 200, 1000, 320)
        patch = image.crop(source)
        image.paste(patch, (640, 340))
        return self._encode(image)
