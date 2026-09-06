"""Turning coded document dates into calendar dates, and judging them.

A machine-readable zone codes a date as six digits, `YYMMDD`, with **no
century**. ICAO Doc 9303 does not fully specify how to recover it, so the rule
below is a policy choice made here, and it has a direct false-rejection cost:
resolve an expiry into the wrong century and a valid passport reads as expired.

The rule:

* **Birth dates** resolve into the hundred years ending today. The result is
  unique, because two candidates a century apart cannot both fall in a
  hundred-year window. When the older candidate would still be a plausible
  living age — over a century old — the result is flagged `ambiguous` so the
  officer is told rather than the system quietly choosing.
* **Expiry and issue dates** resolve to the candidate closest to today.
  Travel documents are valid for at most about ten years, so the nearest
  century is right in every realistic case, and the alternatives are at least
  fifty years away.

A date whose day does not exist raises rather than being repaired. Note that
one candidate can be invalid while the other is fine: 1900 was not a leap year
and 2000 was, so `000229` has exactly one real reading.

Known limitation: some issuers code an unknown day or month as filler or as
`00`. That is rejected here as malformed, which a detector reports as a check
that did not happen rather than a check that failed. Worth revisiting when a
real specimen shows it.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from core.standards.errors import DateFormatError

CODED_LENGTH: Final[int] = 6
"""A coded date is exactly six characters, `YYMMDD`."""

_DIGITS: Final[frozenset[str]] = frozenset("0123456789")

CENTURIES: Final[tuple[int, ...]] = (1900, 2000, 2100)
"""The centuries a two-digit year could belong to."""

MAX_HUMAN_AGE_YEARS: Final[int] = 120
"""Beyond this, a birth date is not a plausible living person."""

DOCUMENT_DATE_WINDOW_YEARS: Final[int] = 50
"""How far from today an issue or expiry date can plausibly sit."""


class DateKind(StrEnum):
    """What a coded date is for. Decides how its century is recovered."""

    BIRTH = "BIRTH"
    """Resolves into the hundred years ending today. Never in the future."""

    EXPIRY = "EXPIRY"
    """Resolves to the century nearest today. May be in the past."""

    ISSUE = "ISSUE"
    """Resolves to the century nearest today. Never after the expiry."""


@dataclass(frozen=True)
class InterpretedDate:
    """A coded date, resolved to a calendar date, with its ambiguity stated."""

    raw: str
    """The six coded characters, unchanged."""

    value: datetime.date
    """The resolved date."""

    ambiguous: bool
    """Whether another century would also have been plausible. Show this to the officer."""

    alternative: datetime.date | None
    """The runner-up reading, when there is one.

    For a birth date this is the next most recent reading that has already
    happened. For a document date it is the next closest to today.
    """


def _shift_years(day: datetime.date, years: int) -> datetime.date:
    """Return the same day a whole number of years away, folding 29 February back to 28.

    The fold is needed in both directions: shifting 29 February by any number
    of years usually lands on a date that does not exist.
    """
    try:
        return day.replace(year=day.year + years)
    except ValueError:
        return day.replace(year=day.year + years, day=28)


def _candidates(raw: str) -> tuple[datetime.date, ...]:
    """Return every real calendar date the coded value could denote.

    Raises:
        DateFormatError: If the value is not six digits, or names a day that
            exists in no century.
    """
    if len(raw) != CODED_LENGTH or not _DIGITS.issuperset(raw):
        msg = f"a coded date is six digits, this is {raw!r}"
        raise DateFormatError(msg)

    year, month, day = int(raw[0:2]), int(raw[2:4]), int(raw[4:6])
    found: list[datetime.date] = []
    for century in CENTURIES:
        try:
            found.append(datetime.date(century + year, month, day))
        except ValueError:
            continue

    if not found:
        msg = f"{raw!r} does not name a day that exists"
        raise DateFormatError(msg)
    return tuple(found)


def _is_plausible(candidate: datetime.date, kind: DateKind, today: datetime.date) -> bool:
    """Report whether a candidate reading is plausible for its kind."""
    if kind is DateKind.BIRTH:
        return _shift_years(today, -MAX_HUMAN_AGE_YEARS) <= candidate <= today
    earliest = _shift_years(today, -DOCUMENT_DATE_WINDOW_YEARS)
    latest = _shift_years(today, DOCUMENT_DATE_WINDOW_YEARS)
    return earliest <= candidate <= latest


def interpret_yymmdd(raw: str, *, kind: DateKind, today: datetime.date) -> InterpretedDate:
    """Recover the century of a coded date.

    Args:
        raw: The six coded characters.
        kind: What the date is for, which decides the resolution rule.
        today: The date to resolve against. Passed in rather than read, so this
            function stays pure and a case can be replayed years later and give
            the same answer.

    Returns:
        The resolved date, and whether another reading was also plausible.

    Raises:
        DateFormatError: If the value is malformed, names a day that exists in
            no century, or is a birth date that could only be in the future.
    """
    candidates = _candidates(raw)

    if kind is DateKind.BIRTH:
        eligible = [candidate for candidate in candidates if candidate <= today]
        if not eligible:
            msg = f"{raw!r} can only be read as a date of birth in the future"
            raise DateFormatError(msg)
        ordered = sorted(eligible, reverse=True)
    else:
        ordered = sorted(candidates, key=lambda candidate: abs((candidate - today).days))

    value = ordered[0]
    alternative = ordered[1] if len(ordered) > 1 else None
    ambiguous = alternative is not None and _is_plausible(alternative, kind, today)

    return InterpretedDate(raw=raw, value=value, ambiguous=ambiguous, alternative=alternative)


def is_expired(expiry: datetime.date, *, on: datetime.date) -> bool:
    """Report whether a document is expired.

    A document is valid through the whole of its expiry date, so it becomes
    expired the day after.

    Args:
        expiry: The expiry date.
        on: The date to judge against, normally the day of the crossing.

    Returns:
        Whether the document has expired.
    """
    return expiry < on


def is_plausible_birth_date(
    birth: datetime.date, *, on: datetime.date, max_age_years: int = MAX_HUMAN_AGE_YEARS
) -> bool:
    """Report whether a birth date could belong to a living person.

    Args:
        birth: The birth date.
        on: The date to judge against.
        max_age_years: The oldest age treated as possible.

    Returns:
        Whether the date is neither in the future nor implausibly distant.
    """
    return _shift_years(on, -max_age_years) <= birth <= on


def issued_before_expiry(issue: datetime.date, expiry: datetime.date) -> bool:
    """Report whether a document was issued before it expires.

    A document whose issue date falls after its expiry date is internally
    contradictory, which no genuine issuing process produces.

    Args:
        issue: The issue date.
        expiry: The expiry date.

    Returns:
        Whether the two are in the right order.
    """
    return issue < expiry
