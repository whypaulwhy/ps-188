"""ICAO Doc 9303 Part 3 check-digit arithmetic over machine-readable zone fields.

Each digit is a weighted sum modulo ten, with the weights 7, 3, 1 repeating
across the field. Letters count as their position in the alphabet plus ten, and
the filler character counts as zero.

What this catches and what it does not, stated plainly because the difference
decides how much weight a detector may put on it:

* It catches a coded field altered in place, most of the time.
* It does **not** catch every adjacent transposition. Swapping two neighbouring
  characters changes the weighted sum by their difference times the difference
  of their weights, which is a multiple of ten whenever the two characters
  differ by five in the 7-3 position. Those swaps are invisible.
* It catches nothing at all about a wholly fabricated document. The arithmetic
  is public, so a forger computes it correctly.

Reference: ICAO Doc 9303 Part 3 s.4.2.2.
"""

from __future__ import annotations

from typing import Final

from core.standards.errors import MrzFormatError

FILLER: Final[str] = "<"
"""The filler character. Counts as zero in the weighted sum."""

WEIGHTS: Final[tuple[int, int, int]] = (7, 3, 1)
"""The repeating weight pattern, applied from the left of the field."""

_UPPERCASE_OFFSET: Final[int] = ord("A") - 10
"""Maps A to 10, B to 11, and so on to Z at 35."""


def character_value(character: str) -> int:
    """Return the numeric value of one machine-readable zone character.

    Args:
        character: A single character from the permitted set: `0`-`9`, `A`-`Z`,
            or the filler `<`.

    Returns:
        Zero for filler, the digit itself for `0`-`9`, and ten through
        thirty-five for `A` through `Z`.

    Raises:
        MrzFormatError: If the character is outside the permitted set.
    """
    if character == FILLER:
        return 0
    if "0" <= character <= "9":
        return ord(character) - ord("0")
    if "A" <= character <= "Z":
        return ord(character) - _UPPERCASE_OFFSET
    msg = f"{character!r} is not a permitted machine-readable zone character"
    raise MrzFormatError(msg)


def compute_check_digit(field: str) -> str:
    """Return the check digit for one field, by the 7-3-1 weighting.

    Args:
        field: The field the digit protects, filler characters included.

    Returns:
        A single character, `0` through `9`.

    Raises:
        MrzFormatError: If the field is empty or holds a character outside the
            permitted set.
    """
    if not field:
        msg = "a check digit cannot be computed over an empty field"
        raise MrzFormatError(msg)
    total = sum(
        character_value(character) * WEIGHTS[position % 3]
        for position, character in enumerate(field)
    )
    return str(total % 10)


def check_digit_matches(field: str, printed: str) -> bool:
    """Report whether the digit printed on a document matches the field beside it.

    One deliberate leniency. When an optional field is entirely filler, some
    issuers print `<` in place of the check digit rather than `0`, and both are
    accepted in practice. Treating that as a mismatch would reject genuine
    passports for a printing convention, which `docs/threat-model.md` counts as
    a first-order harm. The leniency applies only when the field itself is
    entirely filler, so it cannot mask an altered value.

    Args:
        field: The field the digit protects.
        printed: The single character printed as the check digit.

    Returns:
        Whether the two agree.

    Raises:
        MrzFormatError: If the field is empty or malformed, or if `printed` is
            not a single character.
    """
    if len(printed) != 1:
        msg = "a check digit is exactly one character"
        raise MrzFormatError(msg)
    if printed == FILLER and set(field) == {FILLER}:
        return True
    return compute_check_digit(field) == printed
