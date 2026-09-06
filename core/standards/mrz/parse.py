"""Parsing the ICAO Doc 9303 machine-readable zone into typed fields.

Only TD3, the passport format, is implemented. `docs/scope.md` accepts no other
machine-readable document, so TD1 and TD2 are deliberately absent rather than
written speculatively. The layout is a table, so adding one is a table entry
and a length constant once a real specimen shows it is needed.

The parser is **strict about shape and lenient about content**. Wrong line
count, wrong length or a character outside the permitted set raises
`MrzFormatError`, because none of those can be reasoned about. A strip that is
structurally sound but says something odd — an empty name, an impossible date —
parses cleanly and is left for a detector to judge. That split exists so a bad
scan produces "not checked" while a bad document produces "failed".

Reference: ICAO Doc 9303 Part 3 s.4.2.
"""

from __future__ import annotations

import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from core.standards.errors import MrzFormatError
from core.standards.mrz.check_digits import FILLER, check_digit_matches, compute_check_digit

TD3: Final[str] = "TD3"
"""The passport format: two lines of forty-four characters."""

TD3_LINE_LENGTH: Final[int] = 44
TD3_LINE_COUNT: Final[int] = 2
TD3_NAME_LENGTH: Final[int] = 39

PERMITTED: Final[frozenset[str]] = frozenset(string.ascii_uppercase + string.digits + FILLER)
"""The complete machine-readable zone character set."""

NAME_SEPARATOR: Final[str] = "<<"
"""Separates the surname from the given names within the name field."""

COMPOSITE: Final[str] = "composite"
"""Name of the check digit computed over most of the second line."""


@dataclass(frozen=True)
class MrzDocument:
    """One parsed machine-readable zone.

    Every value is the raw text as printed, with trailing filler removed only
    where filler is padding rather than data. Dates stay as their six coded
    characters; turning them into calendar dates needs a century rule and lives
    in `core.standards.date_rules`.
    """

    mrz_format: str
    document_code: str
    issuing_state: str
    surname: str
    given_names: tuple[str, ...]
    document_number: str
    nationality: str
    date_of_birth: str
    sex: str
    date_of_expiry: str
    optional_data: str
    check_digits: Mapping[str, str]
    lines: tuple[str, ...]


@dataclass(frozen=True)
class CheckDigitResult:
    """One check digit, recomputed and compared with the one on the document."""

    name: str
    field: str
    printed: str
    computed: str
    matches: bool


def _require_permitted_characters(line: str, index: int) -> None:
    """Reject a line holding a character outside the permitted set."""
    for character in line:
        if character not in PERMITTED:
            msg = (
                f"line {index + 1} contains {character!r}, which is not a permitted "
                f"machine-readable zone character"
            )
            raise MrzFormatError(msg)


def _split_name(field: str) -> tuple[str, tuple[str, ...]]:
    """Split the name field into a surname and given names.

    Args:
        field: The thirty-nine character name field.

    Returns:
        The surname, and the given names in order. Either may be empty; an
        empty name is a content problem for a detector, not a shape problem.
    """
    trimmed = field.rstrip(FILLER)
    surname, separator, given = trimmed.partition(NAME_SEPARATOR)
    if not separator:
        return surname.replace(FILLER, " ").strip(), ()
    parts = tuple(part for part in given.split(FILLER) if part)
    return surname.replace(FILLER, " ").strip(), parts


def parse_td3(lines: Sequence[str]) -> MrzDocument:
    """Parse a TD3 machine-readable zone.

    Args:
        lines: The two strip lines. Surrounding whitespace is removed; nothing
            else is repaired.

    Returns:
        The parsed zone.

    Raises:
        MrzFormatError: If there are not exactly two lines, if either is not
            forty-four characters, or if any character is outside the permitted
            set.
    """
    cleaned = tuple(line.strip() for line in lines)

    if len(cleaned) != TD3_LINE_COUNT:
        msg = f"a passport strip has {TD3_LINE_COUNT} lines, this has {len(cleaned)}"
        raise MrzFormatError(msg)

    for index, line in enumerate(cleaned):
        if len(line) != TD3_LINE_LENGTH:
            msg = (
                f"line {index + 1} of a passport strip is {TD3_LINE_LENGTH} characters, "
                f"this one is {len(line)}"
            )
            raise MrzFormatError(msg)
        _require_permitted_characters(line, index)

    first, second = cleaned
    surname, given_names = _split_name(first[5:44])

    return MrzDocument(
        mrz_format=TD3,
        document_code=first[0:2],
        issuing_state=first[2:5],
        surname=surname,
        given_names=given_names,
        document_number=second[0:9],
        nationality=second[10:13],
        date_of_birth=second[13:19],
        sex=second[20:21],
        date_of_expiry=second[21:27],
        optional_data=second[28:42],
        check_digits={
            "document_number": second[9],
            "date_of_birth": second[19],
            "date_of_expiry": second[27],
            "optional_data": second[42],
            COMPOSITE: second[43],
        },
        lines=cleaned,
    )


def parse_mrz(lines: Sequence[str]) -> MrzDocument:
    """Parse a machine-readable zone of any supported format.

    Only TD3 is supported, so this is currently a strict alias with a clearer
    failure message. It exists so that callers do not have to know the format
    in advance, and so that adding a format later changes one function.

    Args:
        lines: The strip lines as read.

    Returns:
        The parsed zone.

    Raises:
        MrzFormatError: If the strip does not match a supported format.
    """
    return parse_td3(lines)


def composite_field(document: MrzDocument) -> str:
    """Return the text the composite check digit is computed over.

    For TD3 that is the document number and its check digit, the date of birth
    and its check digit, and everything from the expiry date to the end of the
    optional data check digit.

    Args:
        document: The parsed zone.

    Returns:
        The concatenated source text.
    """
    second = document.lines[1]
    return second[0:10] + second[13:20] + second[21:43]


def verify_check_digits(document: MrzDocument) -> tuple[CheckDigitResult, ...]:
    """Recompute every check digit on a strip and compare it with the printed one.

    Args:
        document: The parsed zone.

    Returns:
        One result per check digit, in the order they appear on the strip.
        `matches` accounts for the filler leniency described in
        `core.standards.mrz.check_digits.check_digit_matches`.
    """
    protected: tuple[tuple[str, str], ...] = (
        ("document_number", document.document_number),
        ("date_of_birth", document.date_of_birth),
        ("date_of_expiry", document.date_of_expiry),
        ("optional_data", document.optional_data),
        (COMPOSITE, composite_field(document)),
    )
    return tuple(
        CheckDigitResult(
            name=name,
            field=field,
            printed=document.check_digits[name],
            computed=compute_check_digit(field),
            matches=check_digit_matches(field, document.check_digits[name]),
        )
        for name, field in protected
    )


def _fit(value: str, width: int, label: str) -> str:
    """Pad a value to a fixed width with filler, refusing to truncate it."""
    if len(value) > width:
        msg = f"{label} is {len(value)} characters, which does not fit in {width}"
        raise MrzFormatError(msg)
    return value.ljust(width, FILLER)


def render_td3(
    *,
    document_code: str,
    issuing_state: str,
    surname: str,
    given_names: Sequence[str],
    document_number: str,
    nationality: str,
    date_of_birth: str,
    sex: str,
    date_of_expiry: str,
    optional_data: str = "",
) -> tuple[str, str]:
    """Build a TD3 strip with correct check digits.

    This exists so that parsing can be round-trip tested over generated input,
    and so that phase 6 can produce synthetic specimens without reimplementing
    the layout. It refuses to truncate an over-long value, because silently
    shortening a name is how a test fixture stops representing what it claims
    to represent.

    Args:
        document_code: Up to two characters, for example `P<`.
        issuing_state: Three characters.
        surname: The primary identifier.
        given_names: The secondary identifiers, in order.
        document_number: Up to nine characters.
        nationality: Three characters.
        date_of_birth: Six coded characters, `YYMMDD`.
        sex: One character.
        date_of_expiry: Six coded characters, `YYMMDD`.
        optional_data: Up to fourteen characters, usually a personal number.

    Returns:
        The two strip lines.

    Raises:
        MrzFormatError: If any value is too long for its field, or if the
            result holds a character outside the permitted set.
    """
    name = surname + NAME_SEPARATOR + FILLER.join(given_names) if given_names else surname
    first = (
        _fit(document_code, 2, "document code")
        + _fit(issuing_state, 3, "issuing state")
        + _fit(name, TD3_NAME_LENGTH, "name")
    )

    number = _fit(document_number, 9, "document number")
    born = _fit(date_of_birth, 6, "date of birth")
    expires = _fit(date_of_expiry, 6, "date of expiry")
    optional = _fit(optional_data, 14, "optional data")
    body = (
        number
        + compute_check_digit(number)
        + _fit(nationality, 3, "nationality")
        + born
        + compute_check_digit(born)
        + _fit(sex, 1, "sex")
        + expires
        + compute_check_digit(expires)
        + optional
        + compute_check_digit(optional)
    )
    second = body + compute_check_digit(body[0:10] + body[13:20] + body[21:43])

    for index, line in enumerate((first, second)):
        _require_permitted_characters(line, index)
    return first, second
