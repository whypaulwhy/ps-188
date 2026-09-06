"""Base class every forgery generator implements.

A forgery here is a **reproducible transformation of a synthetic specimen with
known ground truth**. It exists so that a detector can be measured against a
document whose alterations are exactly known, and for no other purpose.

Every generator states, in `alters`, what it changed. That is what an
evaluation run scores against: without it a detection rate would be a claim
about data nobody characterised.

Note what is absent. Nothing here imitates a real issuer, and nothing generates
a human face. See :mod:`datagen.synthetic_docs`.
"""

from __future__ import annotations

import io
from typing import Any

from PIL import Image

from datagen.synthetic_docs import Specimen


class Forgery:
    """One reproducible forgery transformation applied to a synthetic specimen."""

    name: str = "forgery"
    """Stable identifier, recorded in an evaluation report."""

    alters: str = "nothing"
    """What this transformation changes, in words an evaluation report can carry."""

    def apply(self, specimen: Specimen, *, seed: int) -> bytes:
        """Return a forged copy of a specimen, PNG encoded.

        Args:
            specimen: The genuine document to alter.
            seed: Makes the alteration reproducible.

        Returns:
            The altered document.
        """
        raise NotImplementedError

    @staticmethod
    def _open(specimen: Specimen) -> Image.Image:
        """Open a specimen for editing."""
        return Image.open(io.BytesIO(specimen.png)).convert("RGB")

    @staticmethod
    def _encode(image: Any) -> bytes:  # noqa: ANN401 - a PIL image; datagen stays untyped here
        """Encode an edited document back to PNG."""
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()
