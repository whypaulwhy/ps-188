"""Extraction: finding the strip, reading what can be read, saying what cannot.

Every function here is allowed to fail. None of them is allowed to crash, and
none of them is allowed to guess.
"""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from datagen.synthetic_docs import generate_specimen
from extraction.mrz_locate import locate_mrz
from extraction.ocr_adapter import read_mrz, tesseract_path
from extraction.preprocess import decode, normalise
from extraction.qr_decode import decode_qr

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


def test_a_document_with_no_code_decodes_to_nothing() -> None:
    """An empty result with no reason means there was no code, not that reading failed."""
    payloads, reason = decode_qr(Image.new("RGB", (50, 50), (255, 255, 255)))

    assert payloads == []
    assert reason is None


@pytest.mark.skipif(tesseract_path() is not None, reason="Tesseract is installed here")
def test_without_a_reader_the_strip_is_reported_unread_rather_than_guessed() -> None:
    """The honest degradation path, and the one this deployment is currently on.

    A general text recogniser reads the second strip line backwards, so this
    project does not use one for the strip. With no character-restricted reader
    installed, the answer is that it was not read.
    """
    region = locate_mrz(grey())
    assert region is not None

    reading = read_mrz(region.crop(grey()))

    assert reading.lines == ()
    assert not reading.complete
    assert reading.reason is not None
    assert "no reader installed" in reading.reason
