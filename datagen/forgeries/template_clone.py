"""Forgery type: a whole document fabricated from a cloned template.

The hardest case for this system and the one it is most honest about. Every
field is invented but internally consistent, every check digit is computed
correctly, and the layout matches because the template was copied. Rung 1 sees
nothing wrong. Only a signature the forger cannot produce settles it, which is
why Rung 0 matters so much and why its absence on most documents at these
crossings is the central finding in `docs/scope.md`.
"""

from __future__ import annotations

from datagen.forgeries.base import Forgery
from datagen.synthetic_docs import Specimen, generate_specimen


class TemplateClone(Forgery):
    """Fabricate a whole document from a cloned template with invented data."""

    name = "template_clone"
    alters = "every field, while remaining internally consistent and correctly formatted"

    def apply(self, specimen: Specimen, *, seed: int) -> bytes:
        """Generate a different document in the same template."""
        return generate_specimen(
            seed=seed,
            surname="INVENTED",
            given_names=("OTHER", "PERSON"),
            document_number="Z9999999",
            date_of_birth="850615",
            date_of_expiry="330615",
        ).png
