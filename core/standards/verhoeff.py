"""Verhoeff checksum, used by UIDAI for the twelfth digit of an Aadhaar number.

Verhoeff is a dihedral-group checksum. Its value over a naive modulo scheme is
that it detects **every** single-digit substitution and **every** transposition
of two adjacent digits — the two mistakes a human makes when copying a number
by hand. Both guarantees are asserted as properties in the tests rather than
taken on trust.

The three tables below are the published ones and are not derived here. They
are the multiplication table of the dihedral group of order ten, a permutation
applied by position, and the inverse table.

Nothing in this module stores or logs a number. Callers hold the digits; this
module answers a question about them and returns.
"""

from __future__ import annotations

from typing import Final

from core.standards.errors import DigitStringError

_DIGITS: Final[frozenset[str]] = frozenset("0123456789")
"""The only characters accepted. `str.isdigit` is deliberately not used; see DigitStringError."""

_MULTIPLICATION: Final[tuple[tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
"""Multiplication table of the dihedral group of order ten."""

_PERMUTATION: Final[tuple[tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
"""Position-dependent permutation, applied cyclically with period eight."""

_INVERSE: Final[tuple[int, ...]] = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
"""Inverse element for each group member."""


def _require_digits(value: str) -> None:
    """Reject anything that is not a non-empty run of ASCII decimal digits.

    Args:
        value: The candidate string.

    Raises:
        DigitStringError: If the value is empty or holds a non-digit character.
    """
    if not value:
        msg = "a digit string cannot be empty"
        raise DigitStringError(msg)
    if not _DIGITS.issuperset(value):
        msg = "a digit string may contain only the characters 0 to 9"
        raise DigitStringError(msg)


def verhoeff_is_valid(digits: str) -> bool:
    """Report whether a digit string carries a valid Verhoeff checksum.

    The final digit is the check digit; everything before it is the payload.

    Args:
        digits: The complete number, check digit included. For Aadhaar this is
            twelve digits.

    Returns:
        Whether the checksum is satisfied.

    Raises:
        DigitStringError: If the value is empty or not all decimal digits.
    """
    _require_digits(digits)
    checksum = 0
    for position, character in enumerate(reversed(digits)):
        checksum = _MULTIPLICATION[checksum][_PERMUTATION[position % 8][int(character)]]
    return checksum == 0


def verhoeff_digit(payload: str) -> str:
    """Return the check digit that completes a payload.

    Args:
        payload: The number *without* its check digit. For Aadhaar this is
            eleven digits.

    Returns:
        The single digit that makes `payload + digit` valid.

    Raises:
        DigitStringError: If the value is empty or not all decimal digits.
    """
    _require_digits(payload)
    checksum = 0
    for position, character in enumerate(reversed(payload)):
        checksum = _MULTIPLICATION[checksum][_PERMUTATION[(position + 1) % 8][int(character)]]
    return str(_INVERSE[checksum])
