"""The Rung 1 detectors, on the paths the golden fixtures do not reach.

The committed corpus covers the ordinary cases. These cover the edges: a strip
whose overall number is the only one wrong, a document type nobody named, a
date that cannot be read at all, and the boundary on the day a passport
expires.
"""

from __future__ import annotations

import datetime

import pytest

from core.contracts import DocumentType, Result, Rung, Subject, TextZone, ZoneName
from core.standards.mrz.parse import render_td3
from detectors.rung1_deterministic import expiry, mrz_checkdigits
from tests.support import provenance, subject

CROSSING = datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.UTC)


def strip(*, expires: str = "350101", born: str = "900101") -> tuple[str, str]:
    """Render a well-formed TD3 strip with correct check digits."""
    return render_td3(
        document_code="P<",
        issuing_state="IND",
        surname="SPECIMEN",
        given_names=("TEST",),
        document_number="Z0000001",
        nationality="IND",
        date_of_birth=born,
        sex="M",
        date_of_expiry=expires,
    )


def with_strip(lines: tuple[str, ...], *, complete: bool = True, **overrides: object) -> Subject:
    """Build a subject carrying a machine-readable strip."""
    fields: dict[str, object] = {
        "zones": (TextZone(name=ZoneName.MRZ, lines=lines, complete=complete),),
        "provenance": provenance(captured_at=CROSSING, received_at=CROSSING),
    }
    fields.update(overrides)
    return subject(**fields)


def check_digits(document: Subject) -> tuple[Result, tuple[str, ...]]:
    """Run the check-digit detector and return its result and reasons."""
    (item,) = mrz_checkdigits.build().run(document)
    return item.result, item.reasons


def expires_check(document: Subject) -> tuple[Result, tuple[str, ...]]:
    """Run the expiry detector and return its result and reasons."""
    (item,) = expiry.build().run(document)
    return item.result, item.reasons


# ---------------------------------------------------------------------------
# Both detectors always apply
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", [mrz_checkdigits, expiry])
def test_a_detector_reports_rather_than_declining(module: object) -> None:
    """Declining to apply would leave the officer unable to tell it never ran."""
    detector = module.build()  # type: ignore[attr-defined]
    document = subject(zones=())

    assert detector.applies_to(document)
    assert detector.rung is Rung.DETERMINISTIC
    assert len(detector.run(document)) == 1


@pytest.mark.parametrize("module", [mrz_checkdigits, expiry])
def test_a_document_nobody_named_is_described_generically(module: object) -> None:
    """An unlisted document type still produces a readable sentence."""
    detector = module.build()  # type: ignore[attr-defined]
    document = subject(zones=(), declared_type=DocumentType.UNRECOGNISED)

    (item,) = detector.run(document)

    assert item.result is Result.NOT_APPLICABLE
    assert item.reasons[0].startswith("This document")


# ---------------------------------------------------------------------------
# Check digits
# ---------------------------------------------------------------------------


def test_a_consistent_strip_passes() -> None:
    """The ordinary case, over a strip rendered from the layout table."""
    result, reasons = check_digits(with_strip(strip()))

    assert result is Result.PASS
    assert "self-consistent" in reasons[0]


def test_an_incomplete_zone_is_not_checked() -> None:
    """Extraction saying it could not capture the whole strip is taken at its word.

    The lines here are perfectly valid. What makes this not-applicable is the
    zone reporting itself incomplete, which must be honoured even when the text
    happens to parse.
    """
    result, reasons = check_digits(with_strip(strip(), complete=False))

    assert result is Result.NOT_APPLICABLE
    assert "not a sign that the document is false" in reasons[0]


def test_only_the_overall_number_being_wrong_reads_correctly() -> None:
    """A composite-only mismatch must not say the overall number failed 'either'.

    The 'either' wording only makes sense after a field has already been named.
    """
    first, second = strip()
    wrong_composite = "0" if second[43] != "0" else "1"
    result, reasons = check_digits(with_strip((first, second[:43] + wrong_composite)))

    assert result is Result.FAIL
    assert len(reasons) == 1
    assert "although each field on its own does" in reasons[0]


def test_several_wrong_fields_are_each_named() -> None:
    """An officer is told which fields disagree, not merely that something does."""
    first, second = strip()
    broken = second[:9] + ("0" if second[9] != "0" else "1") + second[10:19]
    broken += ("0" if second[19] != "0" else "1") + second[20:]
    result, reasons = check_digits(with_strip((first, broken)))

    assert result is Result.FAIL
    assert any("document number" in reason for reason in reasons)
    assert any("date of birth" in reason for reason in reasons)


def test_no_reason_mentions_a_check_digit() -> None:
    """The phrase this project exists not to put in front of an officer."""
    first, second = strip()
    result, reasons = check_digits(with_strip((first, second[:43] + "9")))

    assert result is Result.FAIL
    assert all("check digit" not in reason.lower() for reason in reasons)


def test_the_digest_falls_back_to_the_provenance_record() -> None:
    """Evidence must always name the bytes it examined, even with no artefact attached."""
    document = with_strip(strip(), artefacts=())

    (item,) = mrz_checkdigits.build().run(document)

    assert item.input_digest == document.provenance.sha256


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_a_valid_document_names_the_date_it_is_good_until() -> None:
    """The officer sees the date, not a verdict word on its own."""
    result, reasons = expires_check(with_strip(strip(expires="350101")))

    assert result is Result.PASS
    assert reasons == ("This document is valid until 01 January 2035.",)


def test_an_expired_document_fails_and_names_the_date() -> None:
    """A rejection has to be explicable to the person being turned back."""
    result, reasons = expires_check(with_strip(strip(expires="200101")))

    assert result is Result.FAIL
    assert reasons == (
        "This document expired on 01 January 2020 and is no longer valid for travel.",
    )


def test_a_document_expiring_on_the_day_of_the_crossing_is_still_valid() -> None:
    """A document is good for the whole of its expiry date, not up to the day before."""
    result, _ = expires_check(with_strip(strip(expires="260101")))

    assert result is Result.PASS


def test_the_day_after_expiry_fails() -> None:
    """The other side of the same boundary."""
    late = datetime.datetime(2026, 1, 2, 12, 0, tzinfo=datetime.UTC)
    document = with_strip(
        strip(expires="260101"), provenance=provenance(captured_at=late, received_at=late)
    )

    assert expires_check(document)[0] is Result.FAIL


def test_an_unreadable_date_is_not_a_failure() -> None:
    """A date that names no real day was not checked, rather than found false."""
    result, reasons = expires_check(with_strip(strip(expires="999999")))

    assert result is Result.NOT_APPLICABLE
    assert reasons == (
        "The expiry date on this document could not be read, so it was not checked.",
    )


def test_the_judgement_is_made_against_the_capture_time() -> None:
    """A case replayed years later reaches the verdict it reached at the barrier.

    The same document is valid when captured in 2026 and expired when captured
    in 2036, and neither answer depends on when the case is re-examined.
    """
    lines = strip(expires="300101")
    later = datetime.datetime(2036, 1, 1, 12, 0, tzinfo=datetime.UTC)

    assert expires_check(with_strip(lines))[0] is Result.PASS
    assert (
        expires_check(
            with_strip(lines, provenance=provenance(captured_at=later, received_at=later))
        )[0]
        is Result.FAIL
    )


def test_a_malformed_strip_is_not_checked() -> None:
    """A strip that does not parse cannot yield a date to judge."""
    result, reasons = expires_check(with_strip(("TOO SHORT", "ALSO SHORT")))

    assert result is Result.NOT_APPLICABLE
    assert "not a sign that the document is false" in reasons[0]
