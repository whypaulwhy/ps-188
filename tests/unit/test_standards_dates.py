"""Recovering the century of a coded date, and judging the result.

The century rule is a policy choice, not a standard, and getting it wrong
rejects a real traveller. These tests pin the rule and the cases where it is
genuinely uncertain.
"""

from __future__ import annotations

import datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.standards.date_rules import (
    DateKind,
    interpret_yymmdd,
    is_expired,
    is_plausible_birth_date,
    issued_before_expiry,
)
from core.standards.errors import DateFormatError

TODAY = datetime.date(2026, 9, 6)
"""A fixed reference date, so every expectation below is stable."""


def interpret(raw: str, kind: DateKind = DateKind.BIRTH, today: datetime.date = TODAY):  # noqa: ANN201
    """Interpret a coded date against the fixed reference date."""
    return interpret_yymmdd(raw, kind=kind, today=today)


# ---------------------------------------------------------------------------
# Birth dates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("900101", datetime.date(1990, 1, 1)),
        ("050101", datetime.date(2005, 1, 1)),
        ("740812", datetime.date(1974, 8, 12)),
        ("260101", datetime.date(2026, 1, 1)),
    ],
)
def test_a_birth_date_resolves_into_the_last_hundred_years(
    raw: str, expected: datetime.date
) -> None:
    """The most recent reading that is not in the future."""
    assert interpret(raw).value == expected


def test_a_birth_date_later_this_year_falls_back_a_century() -> None:
    """A date later in the current year cannot be this year, so it is a century earlier."""
    assert interpret("261201").value == datetime.date(1926, 12, 1)


def test_an_ordinary_birth_date_has_no_second_reading() -> None:
    """Only one reading of 1990 has already happened, so there is nothing to be unsure about."""
    result = interpret("900101")

    assert not result.ambiguous
    assert result.alternative is None


def test_a_centenarian_birth_date_is_flagged_ambiguous() -> None:
    """Both readings are plausible living ages, so the officer is told rather than guessed at.

    Read as 2010 the traveller is 16; read as 1910 they are 116. The system
    picks the recent reading and says out loud that the other one is possible.
    """
    result = interpret("100101")

    assert result.value == datetime.date(2010, 1, 1)
    assert result.alternative == datetime.date(1910, 1, 1)
    assert result.ambiguous


def test_a_birth_date_that_could_only_be_in_the_future_is_refused() -> None:
    """No reading of the value produces a date that has happened."""
    with pytest.raises(DateFormatError, match="in the future"):
        interpret("991231", today=datetime.date(1950, 1, 1))


# ---------------------------------------------------------------------------
# Expiry and issue dates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("350101", datetime.date(2035, 1, 1)),
        ("120415", datetime.date(2012, 4, 15)),
        ("991231", datetime.date(1999, 12, 31)),
        ("300101", datetime.date(2030, 1, 1)),
    ],
)
def test_an_expiry_resolves_to_the_nearest_century(raw: str, expected: datetime.date) -> None:
    """Travel documents are valid for about a decade, so nearest is right."""
    assert interpret(raw, DateKind.EXPIRY).value == expected


def test_an_expiry_far_in_the_future_resolves_backwards() -> None:
    """A passport expiring in 2099 is not plausible; one that expired in 1999 is."""
    result = interpret("991231", DateKind.EXPIRY)

    assert result.value == datetime.date(1999, 12, 31)
    assert not result.ambiguous


def test_an_expiry_is_never_ambiguous() -> None:
    """Candidates are a century apart, so only one can sit within fifty years of today."""
    for year in range(0, 100, 7):
        assert not interpret(f"{year:02d}0601", DateKind.EXPIRY).ambiguous


def test_an_issue_date_uses_the_same_rule_as_an_expiry() -> None:
    """Both are document dates and neither is bounded by a human lifespan."""
    assert interpret("200101", DateKind.ISSUE).value == datetime.date(2020, 1, 1)


# ---------------------------------------------------------------------------
# The leap day
# ---------------------------------------------------------------------------


def test_a_date_valid_in_only_one_century_resolves_to_it() -> None:
    """1900 was not a leap year and 2000 was, so this has exactly one reading."""
    result = interpret("000229")

    assert result.value == datetime.date(2000, 2, 29)
    assert result.alternative is None
    assert not result.ambiguous


def test_a_leap_day_valid_in_two_centuries_keeps_both_readings() -> None:
    """1904 and 2004 were both leap years, so both readings have happened."""
    result = interpret("040229")

    assert result.value == datetime.date(2004, 2, 29)
    assert result.alternative == datetime.date(1904, 2, 29)
    assert not result.ambiguous


def test_the_age_window_folds_a_leap_day_rather_than_crashing() -> None:
    """Shifting 29 February by a year lands on a date that does not exist."""
    assert is_plausible_birth_date(
        datetime.date(2023, 3, 1), on=datetime.date(2024, 2, 29), max_age_years=1
    )
    assert not is_plausible_birth_date(
        datetime.date(2023, 2, 27), on=datetime.date(2024, 2, 29), max_age_years=1
    )


def test_the_document_window_folds_a_leap_day_in_both_directions() -> None:
    """The forward edge of the expiry window has the same problem as the backward one.

    Judged on 29 February, the window runs to 2074, which is not a leap year.
    Computing the edge naively raises; folding to the 28th does not.
    """
    result = interpret_yymmdd("300101", kind=DateKind.EXPIRY, today=datetime.date(2024, 2, 29))

    assert result.value == datetime.date(2030, 1, 1)
    assert result.alternative == datetime.date(1930, 1, 1)
    assert not result.ambiguous


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["90010", "9001011", "", "9001A1", "90 101", "٩٠٠١٠١"])
def test_a_date_that_is_not_six_digits_is_refused(bad: str) -> None:
    """Shape first. Filler and non-Western numerals are both rejected."""
    with pytest.raises(DateFormatError, match="six digits"):
        interpret(bad)


@pytest.mark.parametrize("bad", ["900230", "901301", "900001", "900100"])
def test_a_day_that_exists_in_no_century_is_refused(bad: str) -> None:
    """The thirtieth of February is not a scanning problem, it is not a date."""
    with pytest.raises(DateFormatError, match="does not name a day"):
        interpret(bad)


# ---------------------------------------------------------------------------
# Judgements
# ---------------------------------------------------------------------------


def test_a_document_is_valid_through_the_whole_of_its_expiry_date() -> None:
    """Expiring today is not expired today."""
    assert not is_expired(TODAY, on=TODAY)
    assert not is_expired(TODAY + datetime.timedelta(days=1), on=TODAY)
    assert is_expired(TODAY - datetime.timedelta(days=1), on=TODAY)


@pytest.mark.parametrize(
    ("birth", "plausible"),
    [
        (datetime.date(1990, 1, 1), True),
        (TODAY, True),
        (TODAY + datetime.timedelta(days=1), False),
        (datetime.date(1800, 1, 1), False),
    ],
)
def test_birth_date_plausibility(birth: datetime.date, plausible: bool) -> None:
    """Neither in the future nor implausibly distant."""
    assert is_plausible_birth_date(birth, on=TODAY) is plausible


def test_a_document_issued_after_it_expires_is_contradictory() -> None:
    """No genuine issuing process produces this."""
    assert issued_before_expiry(datetime.date(2020, 1, 1), datetime.date(2030, 1, 1))
    assert not issued_before_expiry(datetime.date(2030, 1, 1), datetime.date(2020, 1, 1))
    assert not issued_before_expiry(TODAY, TODAY)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


coded_dates = st.dates(
    min_value=datetime.date(1930, 1, 1), max_value=datetime.date(2029, 12, 31)
).map(lambda day: day.strftime("%y%m%d"))


@settings(max_examples=300)
@given(raw=coded_dates)
def test_a_birth_date_is_never_resolved_into_the_future(raw: str) -> None:
    """Whatever the input, the chosen reading has already happened."""
    assert interpret(raw, DateKind.BIRTH).value <= TODAY


@settings(max_examples=300)
@given(raw=coded_dates)
def test_a_document_date_resolves_within_fifty_years_of_today(raw: str) -> None:
    """The nearest-century rule cannot place an expiry outside the plausible window."""
    value = interpret(raw, DateKind.EXPIRY).value

    assert abs(value.year - TODAY.year) <= 50


@settings(max_examples=200)
@given(raw=coded_dates, kind=st.sampled_from(list(DateKind)))
def test_interpretation_is_deterministic(raw: str, kind: DateKind) -> None:
    """The same coded value and the same reference date always give the same answer."""
    assert interpret(raw, kind) == interpret(raw, kind)


@settings(max_examples=200)
@given(raw=coded_dates, kind=st.sampled_from(list(DateKind)))
def test_the_raw_value_is_carried_through_unchanged(raw: str, kind: DateKind) -> None:
    """The coded characters stay available for the audit record."""
    assert interpret(raw, kind).raw == raw
