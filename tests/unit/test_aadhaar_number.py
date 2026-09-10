"""The Aadhaar number check: what it may conclude, and what it must not leak.

Two things make this file necessary beyond the golden corpus.

**The passing case cannot be a committed fixture.** A number that passes is a
Verhoeff-valid number beginning 2 to 9 — an issuable Aadhaar number — and
`tests/unit/test_no_raw_identifiers.py` fails the build if one appears in any
committed file. So the passing number is computed here at runtime, exactly as
`test_persistence.py` does, which is also a small proof that the detector and
the repository scan agree about what "issuable" means.

**Nothing it reads may reach the evidence.** Rule 3 applies inside a detector as
much as at the database. The detector sees the number in the clear for as long
as it takes to check the arithmetic, and what comes out is masked.
"""

from __future__ import annotations

import datetime
from typing import Final

import pytest

from core.contracts import (
    Artefact,
    DocumentType,
    Provenance,
    Result,
    Subject,
    TextZone,
    ZoneName,
)
from core.standards.verhoeff import verhoeff_digit
from detectors.rung1_deterministic.aadhaar_number import build, candidates, is_well_formed

CAPTURED_AT: Final[datetime.datetime] = datetime.datetime(2026, 9, 10, 9, 0, tzinfo=datetime.UTC)
DIGEST: Final[str] = "b" * 64


def issuable_number() -> str:
    """Return a number with the shape of a real Aadhaar number, computed here.

    Never written down: a literal would be committed to this repository, and the
    repository scan would rightly fail on it.
    """
    body = "23456789012"
    return body + verhoeff_digit(body)


def subject(
    *lines: str,
    declared: DocumentType = DocumentType.AADHAAR,
    complete: bool = True,
    zone: bool = True,
) -> Subject:
    """Build a subject carrying a printed page with the given lines."""
    zones: tuple[TextZone, ...] = ()
    if zone:
        zones = (TextZone(name=ZoneName.VISUAL_INSPECTION, lines=tuple(lines), complete=complete),)
    return Subject(
        provenance=Provenance(
            source_id="case-aadhaar",
            sha256=DIGEST,
            media_type="image/png",
            byte_size=1024,
            captured_at=CAPTURED_AT,
            received_at=CAPTURED_AT,
            checkpoint_id="ssb-demo-01",
        ),
        declared_type=declared,
        artefacts=(
            Artefact(role="document_front", media_type="image/png", sha256=DIGEST, data=b"x"),
        ),
        zones=zones,
    )


def examine(*lines: str, **kwargs: object) -> tuple[Result, tuple[str, ...]]:
    """Run the detector over a printed page and return its result and reasons."""
    evidence = build().run(subject(*lines, **kwargs))  # type: ignore[arg-type]
    assert len(evidence) == 1
    return evidence[0].result, evidence[0].reasons


# The arithmetic


def test_a_well_formed_number_passes() -> None:
    """Computed at runtime, because a passing number cannot be committed."""
    number = issuable_number()
    grouped = f"{number[0:4]} {number[4:8]} {number[8:12]}"

    result, _ = examine("Government of India", grouped, "SPECIMEN TEST CASE")

    assert result is Result.PASS


def test_a_number_that_fails_the_scheme_is_rejected() -> None:
    """The criterion. A made-up number is one a machine can refuse outright."""
    number = issuable_number()
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)

    result, reasons = examine(f"{wrong[0:4]} {wrong[4:8]} {wrong[8:12]}")

    assert result is Result.FAIL
    assert "cannot be an Aadhaar number" in reasons[0]


def test_a_number_beginning_zero_is_not_issuable() -> None:
    """Numbers beginning 0 or 1 are never issued, which is why fixtures use them."""
    body = "01234567890"
    number = body + verhoeff_digit(body)

    assert is_well_formed(number) is False


def test_the_failure_reason_admits_a_bad_photograph_can_cause_it() -> None:
    """The first-order harm is a genuine card refused. The officer is told so."""
    number = issuable_number()
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)

    _, reasons = examine(f"{wrong[0:4]} {wrong[4:8]} {wrong[8:12]}")

    assert any("photograph it again" in reason for reason in reasons)


def test_a_pass_does_not_claim_the_card_is_genuine() -> None:
    """A well-formed number is not an issued number, and must not read as one."""
    number = issuable_number()

    _, reasons = examine(f"{number[0:4]} {number[4:8]} {number[8:12]}")

    assert any("does not establish" in reason for reason in reasons)


# What it refuses to judge


def test_a_document_not_declared_aadhaar_is_not_judged() -> None:
    """A stray twelve-digit run on a passport is not an Aadhaar number."""
    number = issuable_number()
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)

    result, _ = examine(wrong, declared=DocumentType.INDIAN_PASSPORT)

    assert result is Result.NOT_APPLICABLE


def test_an_incompletely_read_page_is_not_judged() -> None:
    """Judging a partial reading is how a genuine card gets refused."""
    number = issuable_number()
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)

    result, _ = examine(wrong, complete=False)

    assert result is Result.NOT_APPLICABLE


def test_a_page_with_no_zone_at_all_is_not_judged() -> None:
    """A photograph that yielded no printed text establishes nothing."""
    result, reasons = examine(zone=False)

    assert result is Result.NOT_APPLICABLE
    assert "could not be read in full" in reasons[0]


def test_a_page_with_no_twelve_digit_number_is_not_judged() -> None:
    """Nothing to check is not the same as something that failed."""
    result, reasons = examine("Government of India", "SPECIMEN TEST CASE", "DOB 01/01/1990")

    assert result is Result.NOT_APPLICABLE
    assert "No twelve-digit number" in reasons[0]


def test_one_good_candidate_among_noise_is_taken_as_the_number() -> None:
    """Recognition noise must not manufacture a forgery finding.

    A photograph of a card yields other digit runs — a pin code, an enrolment
    number, a phone number. If any candidate is well formed, that is the Aadhaar
    number and the rest are noise.
    """
    number = issuable_number()

    result, _ = examine(
        "1234 5678 9999",
        f"{number[0:4]} {number[4:8]} {number[8:12]}",
        "9876 5432 1000",
    )

    assert result is Result.PASS


# Rule 3, inside the detector


def test_no_reason_contains_the_number_in_the_clear() -> None:
    """The detector reads a number it may never repeat."""
    number = issuable_number()

    _, reasons = examine(f"{number[0:4]} {number[4:8]} {number[8:12]}")

    for reason in reasons:
        assert number not in reason
        assert number[:8] not in reason


def test_a_rejected_number_is_also_masked() -> None:
    """The failing path leaks just as easily as the passing one."""
    number = issuable_number()
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)

    _, reasons = examine(f"{wrong[0:4]} {wrong[4:8]} {wrong[8:12]}")

    for reason in reasons:
        assert wrong not in reason


def test_the_evidence_carries_no_jargon() -> None:
    """CLAUDE.md's officer-facing rule, checked where the words are produced."""
    number = issuable_number()
    wrong = number[:-1] + str((int(number[-1]) + 1) % 10)

    for lines in (
        (f"{number[0:4]} {number[4:8]} {number[8:12]}",),
        (f"{wrong[0:4]} {wrong[4:8]} {wrong[8:12]}",),
    ):
        _, reasons = examine(*lines)
        joined = " ".join(reasons).lower()
        assert "check digit" not in joined
        assert "verhoeff" not in joined
        assert "checksum" not in joined


# Candidate extraction


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("2345 6789 0123", ["234567890123"]),
        ("234567890123", ["234567890123"]),
        ("2345-6789-0123", ["234567890123"]),
        ("no digits here", []),
        ("12345678901234567890", []),
    ],
)
def test_candidate_extraction(line: str, expected: list[str]) -> None:
    """Grouped, unspaced and hyphenated forms all count; a longer run does not."""
    assert candidates((line,)) == expected


def test_a_hex_digest_is_not_mistaken_for_a_number() -> None:
    """A SHA-256 value routinely contains twelve consecutive digits."""
    assert candidates((f"digest {'a1b2c3d4' * 8}",)) == []
