"""Base class every forgery generator implements so each attack type is reproducible from a seed."""

from __future__ import annotations


class Forgery:
    """One reproducible forgery transformation applied to a synthetic specimen."""

    def apply(self, specimen: object, *, seed: int) -> object:
        """Return a forged copy of a specimen. Not yet implemented."""
        raise NotImplementedError("datagen.forgeries.base lands in phase 6")
