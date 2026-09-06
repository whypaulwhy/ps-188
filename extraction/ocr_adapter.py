"""Adapter over RapidOCR and over Tesseract with an OCR-B whitelist for the MRZ zone only."""

from __future__ import annotations


def read_text(image: object, *, zone: str | None = None) -> list[str]:
    """Return recognised text lines for a whole image or one named zone. Not yet implemented."""
    raise NotImplementedError(
        "extraction.ocr_adapter lands in phase 6, with the images that can test it"
    )
