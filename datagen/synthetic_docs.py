"""Generate synthetic specimen documents with known ground truth.

Everything here is for a **fictional issuing state**, in the style of the
"Utopia" specimen ICAO publishes and phase 1 already uses as a fixture. This is
deliberate and not negotiable: a convincing image of a real issuer's document,
with a real issuer's layout and emblem, is a forgery whatever directory it
lives in. What tamper detection needs is *controlled* ground truth, not a real
template.

Every specimen is reproducible from its seed, so a fixture can be regenerated
byte for byte and an evaluation run can be replayed.

The machine-readable strip is drawn **character by character into fixed-width
cells** rather than as a run of text. A real strip is set in OCR-B at a fixed
pitch, and no font this project may redistribute is. Drawing per cell gives the
correct geometry from whatever font is available, which keeps generation
reproducible across machines.
"""

from __future__ import annotations

import io
import random
from dataclasses import dataclass
from typing import Final

from PIL import Image, ImageDraw, ImageFont

from core.standards.mrz.parse import render_td3

CARD_WIDTH: Final[int] = 1040
CARD_HEIGHT: Final[int] = 660
CELL: Final[int] = 22
SCALE: Final[int] = 2

ISSUING_STATE: Final[str] = "UTO"
"""Utopia. A fictional state code reserved for specimens, never a real issuer."""

WATERMARK: Final[str] = "SPECIMEN - UTOPIA - NOT A REAL DOCUMENT"

PAPER: Final[tuple[int, int, int]] = (238, 236, 228)
PANEL: Final[tuple[int, int, int]] = (250, 249, 245)
INK: Final[tuple[int, int, int]] = (18, 18, 22)
FAINT: Final[tuple[int, int, int]] = (120, 120, 126)


@dataclass(frozen=True)
class Specimen:
    """A generated document and the truth about what is on it."""

    png: bytes
    """The rendered document, PNG encoded."""

    mrz: tuple[str, str]
    """The strip as generated. Ground truth for anything that reads it back."""

    fields: dict[str, str]
    """The printed fields, as generated."""

    seed: int
    """The seed that produced this specimen. Regenerating it reproduces the bytes."""

    portrait_box: tuple[int, int, int, int]
    """Where the portrait sits, so a forgery generator can replace exactly that region."""


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Return a font of a given size, bundled with Pillow so it is the same everywhere."""
    return ImageFont.load_default(size=size)


def _draw_strip(draw: ImageDraw.ImageDraw, lines: tuple[str, str], top: int) -> None:
    """Draw the machine-readable strip one character per fixed-width cell."""
    font = _font(CELL)
    for row, line in enumerate(lines):
        baseline = top + row * (CELL + 8)
        for index, character in enumerate(line):
            left = 20 + index * CELL
            draw.text(
                (left + CELL / 2, baseline + (CELL + 6) / 2),
                character,
                font=font,
                fill=INK,
                anchor="mm",
            )


def _draw_portrait(
    draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], rng: random.Random
) -> None:
    """Draw a placeholder portrait.

    A flat panel with a seeded tint, not a face. This project generates no
    synthetic faces: it has no need of one, and producing images of people who
    do not exist to test a border system is a line worth not crossing.
    """
    tint = (rng.randrange(150, 200), rng.randrange(150, 200), rng.randrange(150, 200))
    draw.rectangle(box, fill=tint, outline=FAINT)
    draw.text(
        ((box[0] + box[2]) / 2, (box[1] + box[3]) / 2),
        "PORTRAIT",
        font=_font(18),
        fill=(90, 90, 96),
        anchor="mm",
    )


def generate_specimen(
    *,
    seed: int,
    surname: str = "SPECIMEN",
    given_names: tuple[str, ...] = ("TEST", "CASE"),
    document_number: str = "Z0000001",
    date_of_birth: str = "900101",
    date_of_expiry: str = "350101",
    sex: str = "M",
) -> Specimen:
    """Generate one synthetic specimen document.

    Args:
        seed: Makes the result reproducible. The same seed and arguments give
            byte-identical output.
        surname: Primary identifier printed and coded.
        given_names: Secondary identifiers.
        document_number: Up to nine characters.
        date_of_birth: Six coded characters, `YYMMDD`.
        date_of_expiry: Six coded characters, `YYMMDD`.
        sex: One character.

    Returns:
        The rendered document and the ground truth that produced it.
    """
    rng = random.Random(seed)
    lines = render_td3(
        document_code="P<",
        issuing_state=ISSUING_STATE,
        surname=surname,
        given_names=given_names,
        document_number=document_number,
        nationality=ISSUING_STATE,
        date_of_birth=date_of_birth,
        sex=sex,
        date_of_expiry=date_of_expiry,
    )

    image = Image.new("RGB", (CARD_WIDTH, CARD_HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)
    draw.rectangle([16, 16, CARD_WIDTH - 16, CARD_HEIGHT - 16], fill=PANEL, outline=FAINT)
    draw.text((36, 34), WATERMARK, font=_font(20), fill=FAINT)

    portrait_box = (36, 90, 276, 400)
    _draw_portrait(draw, portrait_box, rng)

    printed = {
        "surname": surname,
        "given_names": " ".join(given_names),
        "document_number": document_number,
        "nationality": ISSUING_STATE,
        "date_of_birth": date_of_birth,
        "date_of_expiry": date_of_expiry,
        "sex": sex,
    }
    label_font, value_font = _font(16), _font(22)
    for row, (label, value) in enumerate(printed.items()):
        top = 100 + row * 44
        draw.text((320, top), label.replace("_", " ").upper(), font=label_font, fill=FAINT)
        draw.text((320, top + 18), value, font=value_font, fill=INK)

    _draw_strip(draw, lines, top=470)

    buffer = io.BytesIO()
    image.resize((CARD_WIDTH * SCALE, CARD_HEIGHT * SCALE), Image.LANCZOS).save(
        buffer, format="PNG"
    )
    return Specimen(
        png=buffer.getvalue(),
        mrz=lines,
        fields=printed,
        seed=seed,
        portrait_box=tuple(value * SCALE for value in portrait_box),  # type: ignore[arg-type]
    )
