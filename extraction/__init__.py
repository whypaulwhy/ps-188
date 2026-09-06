"""Turning a captured file into the regions and text that detectors consume.

Empty until phase 6. This is pixel code, and phase 1 committed data-level
fixtures only, so there is nothing here that could be tested yet. It lands
alongside the synthetic images in ``datagen/``. See
``docs/adr/0004-extraction-contract-in-core.md``.

What a detector receives is not defined here: it is
:class:`core.contracts.subject.Subject`, which lives in ``core`` so that no
detector imports a vision library transitively.
"""
