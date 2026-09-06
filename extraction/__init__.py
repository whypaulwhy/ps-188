"""Turning a captured file into the regions and text that detectors consume.

The seam ADR 0004 describes: everything uncertain about a photograph happens
here, and detectors receive a settled set of facts. Nothing here decides
anything, nothing invents a value, and every failure is recorded in
``Subject.not_extracted`` rather than hidden.

What a detector receives is defined in :class:`core.contracts.subject.Subject`,
which lives in ``core`` so that no detector imports a vision library
transitively.
"""
