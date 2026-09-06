"""The passport strip: check-digit arithmetic and TD3 parsing.

The committed vectors from phase 1 are the anchor here. They were computed from
ICAO Doc 9303 Part 3 before any of this code existed, and five of them
reproduce the published Utopia specimen exactly, so agreeing with them is a
real check rather than a restatement.
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from core.standards.errors import MrzFormatError
from core.standards.mrz.check_digits import (
    character_value,
    check_digit_matches,
    compute_check_digit,
)
from core.standards.mrz.parse import (
    COMPOSITE,
    TD3,
    composite_field,
    parse_mrz,
    parse_td3,
    render_td3,
    verify_check_digits,
)
from tests.golden.harness import discover_cases, load_vectors

VECTORS = load_vectors("mrz_check_digits.json")["vectors"]
CASES = {case.case_id: case for case in discover_cases()}

mrz_fields = st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<", min_size=1, max_size=44)
names = st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=10)
codes = st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=1, max_size=9)


def strip_lines(case_id: str) -> list[str]:
    """Return the two strip lines from a committed golden fixture."""
    return CASES[case_id].input_path.read_text(encoding="utf-8").splitlines()


# ---------------------------------------------------------------------------
# Character values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("character", "value"),
    [("<", 0), ("0", 0), ("9", 9), ("A", 10), ("J", 19), ("Z", 35)],
)
def test_character_values_follow_the_standard(character: str, value: int) -> None:
    """Filler is zero, digits are themselves, letters continue from ten."""
    assert character_value(character) == value


@pytest.mark.parametrize("bad", ["a", "-", " ", "!", "é"])
def test_characters_outside_the_permitted_set_are_refused(bad: str) -> None:
    """A strip holds only uppercase letters, digits and filler."""
    with pytest.raises(MrzFormatError, match="not a permitted"):
        character_value(bad)


# ---------------------------------------------------------------------------
# Check digits, against the committed vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "expected", "note"),
    [(v["field"], v["check_digit"], v["note"]) for v in VECTORS],
    ids=[v["note"] for v in VECTORS],
)
def test_the_committed_vectors_reproduce(field: str, expected: str, note: str) -> None:
    """Every phase-1 vector, including the five from the published specimen."""
    assert compute_check_digit(field) == expected, note


def test_an_empty_field_has_no_check_digit() -> None:
    """There is nothing to weight."""
    with pytest.raises(MrzFormatError, match="empty field"):
        compute_check_digit("")


@settings(max_examples=300)
@given(field=mrz_fields)
def test_a_check_digit_is_always_one_digit(field: str) -> None:
    """Whatever the field, the result is a single character 0 to 9."""
    digit = compute_check_digit(field)

    assert len(digit) == 1
    assert digit in "0123456789"


@settings(max_examples=300)
@given(field=mrz_fields)
def test_a_computed_digit_always_verifies(field: str) -> None:
    """Computation and comparison agree."""
    assert check_digit_matches(field, compute_check_digit(field))


@settings(max_examples=300)
@given(field=mrz_fields)
def test_computation_is_deterministic(field: str) -> None:
    """The same field always produces the same digit."""
    assert compute_check_digit(field) == compute_check_digit(field)


@settings(max_examples=500)
@given(
    field=mrz_fields,
    position=st.integers(min_value=0),
    replacement=st.sampled_from("0123456789"),
)
def test_a_single_digit_change_is_usually_but_not_always_caught(
    field: str, position: int, replacement: str
) -> None:
    """A changed character alters the sum unless the change is a multiple of ten.

    This documents the real strength of the 7-3-1 scheme rather than
    overstating it. A substitution slips through whenever the character's value
    changes by an amount that cancels modulo ten against its weight — which is
    why the strip arithmetic is Rung 1 evidence about internal consistency and
    never proof of anything.
    """
    index = position % len(field)
    assume(field[index] != replacement)
    changed = field[:index] + replacement + field[index + 1 :]

    weight = (7, 3, 1)[index % 3]
    shift = (character_value(replacement) - character_value(field[index])) * weight
    caught = compute_check_digit(changed) != compute_check_digit(field)

    assert caught == (shift % 10 != 0)


def test_the_seven_three_one_scheme_misses_some_transpositions() -> None:
    """A known blind spot, pinned so nobody later claims the scheme catches everything.

    Swapping two adjacent characters at the 7 and 3 weights changes the sum by
    four times their difference. When they differ by five, that is twenty, and
    the check digit does not move.
    """
    assert compute_check_digit("50") == compute_check_digit("05")


# ---------------------------------------------------------------------------
# The filler leniency
# ---------------------------------------------------------------------------


def test_an_unused_optional_field_may_print_filler_instead_of_zero() -> None:
    """Some issuers print `<` rather than `0` when the field is unused."""
    assert check_digit_matches("<<<<<<<<<<<<<<", "<")
    assert check_digit_matches("<<<<<<<<<<<<<<", "0")


def test_the_leniency_does_not_extend_to_fields_with_content() -> None:
    """Filler is accepted only when the field really is empty, so it masks nothing."""
    assert not check_digit_matches("ZE184226B<<<<<", "<")


def test_a_check_digit_is_exactly_one_character() -> None:
    """Two characters is not a check digit, and neither is none."""
    for printed in ("", "12"):
        with pytest.raises(MrzFormatError, match="exactly one character"):
            check_digit_matches("ABC", printed)


# ---------------------------------------------------------------------------
# TD3 parsing, against the committed fixtures
# ---------------------------------------------------------------------------


def test_the_published_specimen_parses() -> None:
    """The ICAO Utopia specimen, field by field."""
    document = parse_td3(strip_lines("td3-icao-specimen"))

    assert document.mrz_format == TD3
    assert document.document_code == "P<"
    assert document.issuing_state == "UTO"
    assert document.surname == "ERIKSSON"
    assert document.given_names == ("ANNA", "MARIA")
    assert document.document_number == "L898902C3"
    assert document.nationality == "UTO"
    assert document.date_of_birth == "740812"
    assert document.sex == "F"
    assert document.date_of_expiry == "120415"
    assert document.optional_data == "ZE184226B<<<<<"


def test_every_check_digit_on_the_published_specimen_matches() -> None:
    """The anchor case. If this breaks, the arithmetic is wrong."""
    results = verify_check_digits(parse_td3(strip_lines("td3-icao-specimen")))

    assert [result.name for result in results] == [
        "document_number",
        "date_of_birth",
        "date_of_expiry",
        "optional_data",
        COMPOSITE,
    ]
    assert all(result.matches for result in results)


def test_the_synthetic_specimen_is_internally_consistent() -> None:
    """The fixture authored in phase 1 verifies against the code written in phase 2."""
    results = verify_check_digits(parse_td3(strip_lines("td3-ind-specimen")))

    assert all(result.matches for result in results)


def test_the_altered_date_of_birth_is_caught() -> None:
    """Exactly the two failures phase 1 predicted, and no others."""
    document = parse_td3(strip_lines("td3-ind-dob-altered"))
    results = {result.name: result for result in verify_check_digits(document)}

    assert not results["date_of_birth"].matches
    assert results["date_of_birth"].printed == "1"
    assert results["date_of_birth"].computed == "2"
    assert not results[COMPOSITE].matches
    assert results[COMPOSITE].computed == "7"
    assert results["document_number"].matches
    assert results["date_of_expiry"].matches


def test_a_truncated_strip_is_malformed_not_failed() -> None:
    """The distinction the whole error hierarchy exists for.

    A strip that could not be read in full raises, so a detector reports a
    check that did not happen. If this returned a failing comparison instead,
    the system would reject travellers for the quality of the scanner.
    """
    with pytest.raises(MrzFormatError, match="44 characters"):
        parse_td3(strip_lines("td3-ind-strip-unreadable"))


# ---------------------------------------------------------------------------
# Shape errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("count", [0, 1, 3])
def test_the_wrong_number_of_lines_is_refused(count: int) -> None:
    """A passport strip has exactly two lines."""
    with pytest.raises(MrzFormatError, match="2 lines"):
        parse_td3(["A" * 44] * count)


def test_a_disallowed_character_is_refused() -> None:
    """Lowercase is not in the machine-readable character set."""
    lines = strip_lines("td3-ind-specimen")
    lines[0] = "p" + lines[0][1:]

    with pytest.raises(MrzFormatError, match="not a permitted"):
        parse_td3(lines)


def test_surrounding_whitespace_is_removed() -> None:
    """OCR output often carries trailing spaces; that is not a document defect."""
    lines = strip_lines("td3-ind-specimen")
    padded = [f"  {lines[0]} ", f"{lines[1]}\t"]

    assert parse_td3(padded).lines == tuple(lines)


def test_parse_mrz_dispatches_to_td3() -> None:
    """The format-agnostic entry point currently supports one format."""
    assert parse_mrz(strip_lines("td3-ind-specimen")).mrz_format == TD3


# ---------------------------------------------------------------------------
# Name splitting
# ---------------------------------------------------------------------------


def test_a_name_with_no_given_names_is_all_surname() -> None:
    """Some documents carry a single name."""
    first, second = render_td3(
        document_code="P<",
        issuing_state="IND",
        surname="SPECIMEN",
        given_names=(),
        document_number="Z0000001",
        nationality="IND",
        date_of_birth="900101",
        sex="M",
        date_of_expiry="350101",
    )
    document = parse_td3([first, second])

    assert document.surname == "SPECIMEN"
    assert document.given_names == ()


def test_an_empty_name_field_parses_rather_than_raising() -> None:
    """Shape is strict, content is not. An empty name is a detector's problem."""
    lines = strip_lines("td3-ind-specimen")
    lines[0] = lines[0][:5] + "<" * 39
    document = parse_td3(lines)

    assert document.surname == ""
    assert document.given_names == ()


# ---------------------------------------------------------------------------
# Rendering, and the round trip
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    surname=names,
    given_names=st.lists(names, min_size=0, max_size=2),
    document_number=codes,
    date_of_birth=st.sampled_from(["900101", "740812", "000229", "651231"]),
    date_of_expiry=st.sampled_from(["350101", "120415", "301231"]),
    sex=st.sampled_from(["M", "F", "<"]),
)
def test_rendering_and_parsing_round_trip(
    surname: str,
    given_names: list[str],
    document_number: str,
    date_of_birth: str,
    date_of_expiry: str,
    sex: str,
) -> None:
    """Anything this renders, the parser reads back unchanged.

    The round trip is what makes the layout table trustworthy: an off-by-one in
    any field offset breaks it.
    """
    lines = render_td3(
        document_code="P<",
        issuing_state="IND",
        surname=surname,
        given_names=given_names,
        document_number=document_number,
        nationality="IND",
        date_of_birth=date_of_birth,
        sex=sex,
        date_of_expiry=date_of_expiry,
    )
    document = parse_td3(list(lines))

    assert document.surname == surname
    assert document.given_names == tuple(given_names)
    assert document.document_number == document_number.ljust(9, "<")
    assert document.date_of_birth == date_of_birth
    assert document.date_of_expiry == date_of_expiry
    assert document.sex == sex
    assert all(result.matches for result in verify_check_digits(document))


def test_rendering_reproduces_the_committed_synthetic_fixture() -> None:
    """The phase-1 fixture was authored by hand; the renderer must agree with it."""
    expected = strip_lines("td3-ind-specimen")
    rendered = render_td3(
        document_code="P<",
        issuing_state="IND",
        surname="SPECIMEN",
        given_names=("TEST", "CASE"),
        document_number="Z0000001",
        nationality="IND",
        date_of_birth="900101",
        sex="M",
        date_of_expiry="350101",
    )

    assert list(rendered) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("document_number", "TOOLONGNUMBER"),
        ("issuing_state", "TOOLONG"),
        ("nationality", "TOOLONG"),
        ("date_of_birth", "9001011"),
        ("document_code", "PPP"),
    ],
)
def test_rendering_refuses_to_truncate(field: str, value: str) -> None:
    """Silently shortening a value makes a fixture stop representing what it claims to."""
    arguments: dict[str, object] = {
        "document_code": "P<",
        "issuing_state": "IND",
        "surname": "SPECIMEN",
        "given_names": (),
        "document_number": "Z0000001",
        "nationality": "IND",
        "date_of_birth": "900101",
        "sex": "M",
        "date_of_expiry": "350101",
    }
    arguments[field] = value

    with pytest.raises(MrzFormatError, match="does not fit"):
        render_td3(**arguments)  # type: ignore[arg-type]


def test_rendering_refuses_an_over_long_name() -> None:
    """The name field is thirty-nine characters and is not negotiable."""
    with pytest.raises(MrzFormatError, match="does not fit"):
        render_td3(
            document_code="P<",
            issuing_state="IND",
            surname="A" * 40,
            given_names=(),
            document_number="Z0000001",
            nationality="IND",
            date_of_birth="900101",
            sex="M",
            date_of_expiry="350101",
        )


def test_rendering_refuses_characters_outside_the_set() -> None:
    """A lowercase name cannot be encoded on a strip."""
    with pytest.raises(MrzFormatError, match="not a permitted"):
        render_td3(
            document_code="P<",
            issuing_state="IND",
            surname="specimen",
            given_names=(),
            document_number="Z0000001",
            nationality="IND",
            date_of_birth="900101",
            sex="M",
            date_of_expiry="350101",
        )


def test_the_composite_field_covers_the_right_slices() -> None:
    """The composite digit protects the document number, the dates and the optional data."""
    document = parse_td3(strip_lines("td3-icao-specimen"))

    assert composite_field(document) == "L898902C3674081221204159ZE184226B<<<<<1"
