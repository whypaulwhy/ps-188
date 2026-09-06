"""Verhoeff, tested against its two defining guarantees.

Verhoeff is used instead of a simpler modulo scheme because it catches every
single-digit substitution and every adjacent transposition — the two mistakes a
human makes copying a number by hand. Those are stated as properties over
arbitrary input rather than demonstrated on examples, because "correct for the
cases I thought of" is not what a checksum has to be.
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from core.standards.errors import DigitStringError
from core.standards.verhoeff import verhoeff_digit, verhoeff_is_valid
from tests.golden.harness import load_vectors

VECTORS = load_vectors("verhoeff.json")

digit_strings = st.text(alphabet="0123456789", min_size=1, max_size=24)
"""Arbitrary non-empty runs of decimal digits."""


# ---------------------------------------------------------------------------
# Committed vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("number", VECTORS["valid"])
def test_the_committed_valid_vectors_check_out(number: str) -> None:
    """Numbers derived from the published tables in phase 1 must validate."""
    assert verhoeff_is_valid(number)


@pytest.mark.parametrize("number", VECTORS["invalid"])
def test_the_committed_invalid_vectors_are_rejected(number: str) -> None:
    """Numbers with a deliberately wrong final digit must not validate."""
    assert not verhoeff_is_valid(number)


# ---------------------------------------------------------------------------
# The two guarantees
# ---------------------------------------------------------------------------


@settings(max_examples=400)
@given(payload=digit_strings)
def test_a_generated_check_digit_always_validates(payload: str) -> None:
    """Generation and validation agree, for any payload."""
    assert verhoeff_is_valid(payload + verhoeff_digit(payload))


@settings(max_examples=500)
@given(payload=digit_strings, position=st.integers(min_value=0), replacement=st.integers(0, 9))
def test_every_single_digit_substitution_is_detected(
    payload: str, position: int, replacement: int
) -> None:
    """Changing exactly one digit always breaks the checksum.

    This is the first of Verhoeff's two guarantees, and the reason UIDAI uses
    it: a single mistyped digit in an Aadhaar number can never go unnoticed.
    """
    number = payload + verhoeff_digit(payload)
    index = position % len(number)
    assume(number[index] != str(replacement))

    corrupted = number[:index] + str(replacement) + number[index + 1 :]

    assert not verhoeff_is_valid(corrupted)


@settings(max_examples=500)
@given(payload=digit_strings, position=st.integers(min_value=0))
def test_every_adjacent_transposition_is_detected(payload: str, position: int) -> None:
    """Swapping two neighbouring digits always breaks the checksum.

    The second guarantee. Note that the 7-3-1 arithmetic used for the passport
    strip does *not* have this property — see the check-digit tests — which is
    why the two are not interchangeable.
    """
    number = payload + verhoeff_digit(payload)
    assume(len(number) >= 2)
    index = position % (len(number) - 1)
    left, right = number[index], number[index + 1]
    assume(left != right)

    swapped = number[:index] + right + left + number[index + 2 :]

    assert not verhoeff_is_valid(swapped)


@settings(max_examples=200)
@given(payload=digit_strings)
def test_a_check_digit_is_a_single_digit(payload: str) -> None:
    """The output is always one character in the range 0 to 9."""
    digit = verhoeff_digit(payload)

    assert len(digit) == 1
    assert digit in "0123456789"


@settings(max_examples=200)
@given(payload=digit_strings)
def test_generation_is_deterministic(payload: str) -> None:
    """The same payload always produces the same digit."""
    assert verhoeff_digit(payload) == verhoeff_digit(payload)


# ---------------------------------------------------------------------------
# Rejecting things that are not digit strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("function", [verhoeff_is_valid, verhoeff_digit])
def test_an_empty_string_is_refused(function: object) -> None:
    """There is no checksum over nothing."""
    with pytest.raises(DigitStringError, match="cannot be empty"):
        function("")  # type: ignore[operator]


@pytest.mark.parametrize("bad", ["12a45", "12 45", "1234-", "١٢٣٤", "1²34"])
def test_non_digits_are_refused(bad: str) -> None:
    """Anything that is not an ASCII decimal digit is rejected.

    The last two matter more than they look. `str.isdigit` returns True for
    Arabic-Indic numerals and for superscripts, and `int` then behaves
    differently for each — so the guard is written against an explicit
    character set rather than that method.
    """
    with pytest.raises(DigitStringError, match="only the characters 0 to 9"):
        verhoeff_is_valid(bad)


@pytest.mark.parametrize("bad", ["12a45", "١٢٣٤"])
def test_generation_refuses_non_digits_too(bad: str) -> None:
    """The same guard applies on the generating side."""
    with pytest.raises(DigitStringError):
        verhoeff_digit(bad)


def test_a_single_digit_payload_works() -> None:
    """The shortest possible payload is still a payload."""
    assert verhoeff_is_valid("0" + verhoeff_digit("0"))
