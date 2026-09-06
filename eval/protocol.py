"""Named evaluation datasets, and the split rules that make a run reproducible.

A number is meaningless without the dataset it came from. Every protocol here
fixes a seed, a size and a list of forgery types, so that two runs of the same
protocol screen byte-identical documents and any change in the result is a
change in the code.

**Everything here is synthetic.** The specimens are rendered by
:mod:`datagen.synthetic_docs` for a fictional issuing state, in a font that is
not OCR-B. Numbers measured against them describe this repository's own output
and are not a claim about real documents. No real traveller's document has ever
entered an evaluation dataset, and if one ever does it needs its own approval,
its own retention window and its own section in
``docs/evaluation-protocol.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class Protocol:
    """One named, reproducible evaluation dataset."""

    name: str
    """Recorded in every report produced from it."""

    seed: int
    """Fixes the generated documents. Two runs screen identical bytes."""

    genuine_count: int
    """How many unaltered specimens to generate."""

    forgeries: tuple[str, ...]
    """Which forgery generators to apply, one forged document per generator per specimen."""

    description: str
    """What this protocol is for, in a sentence a report can carry."""


SYNTHETIC_V1: Final[Protocol] = Protocol(
    name="synthetic-utopia-v1",
    seed=20260906,
    genuine_count=12,
    forgeries=(
        "photo_substitution",
        "text_field_edit",
        "copy_move",
        "recapture",
        "template_clone",
    ),
    description=(
        "Synthetic specimens for the fictional state Utopia, and one document per "
        "forgery type derived from each. Measures whether a detector separates "
        "altered documents from unaltered ones on data this repository generated."
    ),
)

PROTOCOLS: Final[dict[str, Protocol]] = {SYNTHETIC_V1.name: SYNTHETIC_V1}


def load_protocol(name: str) -> Protocol:
    """Load a named evaluation protocol definition.

    Args:
        name: The protocol name.

    Returns:
        The protocol.

    Raises:
        KeyError: If no protocol has that name. Reports must name a real
            dataset, so a typo fails rather than silently measuring something
            else.
    """
    return PROTOCOLS[name]
