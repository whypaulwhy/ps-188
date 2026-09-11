"""Extraction: finding the strip, reading what can be read, saying what cannot.

Every function here is allowed to fail. None of them is allowed to crash, and
none of them is allowed to guess.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from core.contracts import DOCUMENT_ROLE, LIVE_CAPTURE_ROLE
from datagen.synthetic_docs import generate_specimen
from extraction.mrz_locate import locate_mrz
from extraction.ocr_adapter import read_mrz, tesseract_path, well_formed_strip
from extraction.pipeline import build_subject
from extraction.preprocess import decode, normalise
from extraction.qr_decode import decode_qr, decoder_available
from tests.support import provenance

SPECIMEN = generate_specimen(seed=1)


def grey() -> object:
    """Return the levelled specimen image."""
    return normalise(decode(SPECIMEN.png))


def test_a_capture_decodes_to_an_image() -> None:
    """The ordinary path."""
    image = decode(SPECIMEN.png)

    assert image.shape[2] == 3
    assert image.shape[0] > 100


def test_bytes_that_are_not_an_image_are_refused() -> None:
    """A truncated upload fails loudly here rather than silently downstream."""
    with pytest.raises(ValueError, match="not a readable image"):
        decode(b"this is not a png")


def test_normalising_gives_a_single_channel() -> None:
    """The locator and the readers work on one channel."""
    assert normalise(decode(SPECIMEN.png)).ndim == 2


def test_the_strip_is_found_where_it_was_drawn() -> None:
    """The locator has to agree with the generator, or nothing downstream runs."""
    region = locate_mrz(grey())

    assert region is not None
    assert 900 < region.top < 1000
    assert 60 < region.bottom - region.top < 140


def test_a_document_with_no_strip_returns_nothing() -> None:
    """Most documents at these crossings have no strip. That is not an error."""
    blank = np.full((800, 1200), 240, dtype=np.uint8)

    assert locate_mrz(blank) is None


def test_a_printed_rule_is_not_mistaken_for_a_strip() -> None:
    """A card border spans the full width and is denser than text.

    This is the failure the locator was rewritten to avoid: the first
    implementation locked onto the bottom border of the card.
    """
    image = np.full((800, 1200), 240, dtype=np.uint8)
    image[700:704, 40:1160] = 0

    assert locate_mrz(image) is None


def test_the_crop_stays_inside_the_image() -> None:
    """Padding must not run off the edge and raise."""
    region = locate_mrz(grey())

    assert region is not None
    assert region.crop(grey(), pad=10_000).size > 0


def test_a_document_with_no_code_yields_no_payloads() -> None:
    """The contract, whatever this machine has installed.

    Either the decoder ran and found nothing, or it could not load and says so.
    There is no third outcome, and in particular a blank page never produces a
    payload.

    An earlier version of this test asserted the reason was always None, which
    quietly encoded "the code reader is always installed". It passed here and
    failed on a teammate's machine, where the reader could not load.
    """
    payloads, reason = decode_qr(Image.new("RGB", (50, 50), (255, 255, 255)))

    assert payloads == []
    assert reason is None or "not available" in reason


@pytest.mark.skipif(not decoder_available(), reason="no code reader on this machine")
def test_a_working_decoder_reports_no_reason() -> None:
    """When the reader does load, an empty result carries no excuse with it.

    The distinction matters: an empty list with a reason means nothing was
    checked, and an empty list without one means the document carries no code.
    """
    payloads, reason = decode_qr(Image.new("RGB", (50, 50), (255, 255, 255)))

    assert payloads == []
    assert reason is None


# ---------------------------------------------------------------------------
# The strip reader refuses rather than guesses
# ---------------------------------------------------------------------------


def test_a_well_formed_reading_is_accepted() -> None:
    """Two lines of the right length, in the right alphabet."""
    assert well_formed_strip(("A" * 44, "B" * 44)) == ("A" * 44, "B" * 44)


@pytest.mark.parametrize(
    ("lines", "why"),
    [
        (("A" * 46, "B" * 44), "a line with characters inserted"),
        (("A" * 42, "B" * 44), "a line with characters dropped"),
        (("A" * 44,), "only one line recovered"),
        ((), "nothing recovered"),
        (("a" * 44, "B" * 44), "a character outside the strip alphabet"),
        (("A" * 44, "B" * 44, "C" * 44), "more lines than a passport strip has"),
    ],
)
def test_a_reading_that_cannot_be_vouched_for_is_refused(lines: tuple[str, ...], why: str) -> None:
    """The refusal that stops a bad read manufacturing a rejection.

    A reader that returns forty-six characters for a forty-four character line
    has inserted something, and every field after the insertion is misaligned.
    Passing that to the check-digit detector would fail a genuine document.
    Nothing is repaired here, because trimming a filler run to make the length
    come out is a guess dressed as arithmetic.
    """
    assert well_formed_strip(lines) is None, why


def test_the_reader_never_returns_a_reading_it_does_not_trust() -> None:
    """The contract, whatever reader this machine has installed.

    Either the strip comes back as two well-formed lines, or it comes back
    empty with a reason. There is no third outcome, and in particular there is
    never a partial or repaired strip.
    """
    region = locate_mrz(grey())
    assert region is not None

    reading = read_mrz(region.crop(grey()))

    if reading.complete:
        assert len(reading.lines) == 2
        assert all(len(line) == 44 for line in reading.lines)
        assert reading.reason is None
    else:
        assert reading.lines == ()
        assert reading.reason is not None
        assert reading.reason.endswith(".")


@pytest.mark.skipif(tesseract_path() is None, reason="no strip reader installed")
def test_a_reader_is_found_even_when_it_is_not_on_the_path() -> None:
    """A reader is found even when it is not on the path.

    Its Windows installer does not amend the path, and a checkpoint box is not
    somewhere anyone wants to be debugging environment variables.
    """
    resolved = tesseract_path()

    assert resolved is not None
    assert Path(resolved).is_file()


# ---------------------------------------------------------------------------
# Photographs of the person travel with the document, and nothing is read from them
# ---------------------------------------------------------------------------


def test_photographs_of_the_person_travel_after_the_document_in_order() -> None:
    """The face check compares the first photograph, so the order they were taken must survive."""
    subject = build_subject(
        SPECIMEN.png,
        provenance=provenance(media_type="image/png"),
        live_captures=((b"first", "image/jpeg"), (b"second", "image/jpeg")),
    )

    assert [artefact.role for artefact in subject.artefacts] == [
        DOCUMENT_ROLE,
        LIVE_CAPTURE_ROLE,
        LIVE_CAPTURE_ROLE,
    ]
    assert [artefact.data for artefact in subject.artefacts[1:]] == [b"first", b"second"]
    assert subject.artefacts[1].sha256 == hashlib.sha256(b"first").hexdigest()


def test_an_unreadable_document_still_carries_the_photographs() -> None:
    """The face checks can still say what they found when the document cannot be read."""
    subject = build_subject(
        b"this is not a png",
        provenance=provenance(),
        live_captures=((b"first", "image/jpeg"),),
    )

    assert [artefact.role for artefact in subject.artefacts] == [DOCUMENT_ROLE, LIVE_CAPTURE_ROLE]
