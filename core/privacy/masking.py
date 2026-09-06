"""Display forms for identifiers, for screens, logs and reports.

Masking is the last line rather than the first: the real protection is that raw
numbers are never persisted at all. What this module guarantees is narrower and
still worth having — that a number rendered for a human, or swept into a log
line, shows at most its last few characters.

One rule is worth stating because the obvious implementation gets it wrong. A
value shorter than the number of characters you intend to reveal is masked
**completely**, not revealed in full. `mask_value("12", visible=4)` returns
`XX`, never `12`.

This module deliberately imports nothing from the rest of the package, so that
:mod:`core.privacy.identifiers` can depend on it without a cycle.
"""

from __future__ import annotations

from typing import Final

MASK_CHARACTER: Final[str] = "X"
"""What a hidden character is rendered as."""

DEFAULT_VISIBLE: Final[int] = 4
"""How many trailing characters are shown by default, matching UIDAI's own convention."""

AADHAAR_GROUP: Final[int] = 4
"""Aadhaar numbers are printed in groups of four."""


def mask_value(value: str, *, visible: int = DEFAULT_VISIBLE, group: int | None = None) -> str:
    """Return a display-safe form of an identifier.

    Args:
        value: The identifier to mask.
        visible: How many trailing characters to leave readable. Zero hides
            everything.
        group: When given, insert a space every this many characters, counted
            from the left, for readability.

    Returns:
        The masked form. Empty input returns empty output.

    Raises:
        ValueError: If `visible` is negative, or `group` is not positive.
    """
    if visible < 0:
        msg = "visible cannot be negative"
        raise ValueError(msg)
    if group is not None and group < 1:
        msg = "group must be at least one character"
        raise ValueError(msg)

    # A value no longer than the reveal window is hidden completely. Revealing
    # it in full would be the exact opposite of what the caller asked for.
    hidden = len(value) if len(value) <= visible else len(value) - visible
    masked = MASK_CHARACTER * hidden + value[hidden:]

    if group is None:
        return masked
    return " ".join(masked[index : index + group] for index in range(0, len(masked), group))


def mask_aadhaar(value: str) -> str:
    """Return an Aadhaar number in the form UIDAI itself uses for display.

    Args:
        value: The twelve digits, with or without spacing.

    Returns:
        The masked number, for example `XXXX XXXX 1234`.
    """
    compact = value.replace(" ", "").replace("-", "")
    return mask_value(compact, visible=DEFAULT_VISIBLE, group=AADHAAR_GROUP)
