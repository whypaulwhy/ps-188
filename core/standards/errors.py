"""What goes wrong when a document does not match the standard it claims to follow.

These are raised by `core.standards` and caught by detectors, which turn them
into `Evidence`. A detector never lets one escape: an unparseable strip is a
result to report, not a crash.

The distinction that matters is between *malformed* and *wrong*. A strip that
cannot be parsed at all is malformed, and the honest answer is that the check
did not happen — `NOT_APPLICABLE`, not `FAIL`. A strip that parses cleanly and
fails its own arithmetic is wrong, and that is a `FAIL`. Confusing the two
means rejecting travellers for the quality of the scanner, which
`docs/threat-model.md` treats as a first-order harm.
"""

from __future__ import annotations


class StandardsError(ValueError):
    """Base class for every violation of a document standard."""


class MrzFormatError(StandardsError):
    """The machine-readable zone does not have the shape the standard requires.

    Wrong number of lines, wrong line length, or a character outside the
    permitted set. Says nothing about whether the document is genuine.
    """


class DigitStringError(StandardsError):
    """A value that must be decimal digits contains something else.

    Raised by the Verhoeff routines. Note that Python's `str.isdigit` is not a
    sufficient guard here: it accepts superscripts and non-Western numerals
    that `int` then refuses.
    """


class DateFormatError(StandardsError):
    """A date is not six digits, or names a day that does not exist."""
