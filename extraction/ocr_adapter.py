"""Reading text off a document, and being honest about when we cannot.

Two backends, because the two jobs are genuinely different.

**RapidOCR reads the printed page.** It is a general text recogniser and it is
good at that.

**The machine-readable strip needs Tesseract with an OCR-B whitelist**, exactly
as the stack in CLAUDE.md specifies. This is not a preference. Measured on this
project's own synthetic specimens, RapidOCR reads the first strip line
correctly and reads the second one **backwards** — the recovered text ends with
the characters the line begins with, and the filler character `<` comes back as
`>`. A general recogniser has no linguistic context to orient a dense
alphanumeric run, so its direction classifier flips it. Cropping the line and
feeding it alone does not help.

**The strip is therefore not read by guesswork.** It would be easy to reverse
the string and map `>` back to `<`, and it would be wrong: individual characters
are also substituted, so the recovered strip would be plausible and incorrect.
Feeding that into the check-digit detector manufactures failures on genuine
documents, and `docs/threat-model.md` treats a traveller wrongly turned back as
a first-order harm. When the strip cannot be read properly, this module says so
and the zone is marked incomplete, which every Rung 1 detector already reports
as a check that did not happen.

Neither backend is imported at module load. A deployment without Tesseract
starts normally and says what it cannot do.
"""

from __future__ import annotations

import shutil
import subprocess  # Tesseract is a local binary, invoked with a fixed argument list
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

MRZ_ALPHABET: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<"
"""The complete machine-readable zone character set, used as the Tesseract whitelist."""

TESSERACT_MISSING: Final[str] = (
    "The machine-readable strip was found but could not be read, because this "
    "checkpoint has no reader installed for the special typeface it uses."
)
RAPIDOCR_MISSING: Final[str] = (
    "The printed text on this document could not be read, because the text "
    "reader is not available at this checkpoint."
)


@dataclass(frozen=True)
class TextReading:
    """What a reader recovered, and whether it trusts the result."""

    lines: tuple[str, ...]
    """The recovered lines, in reading order. Empty when nothing was read."""

    complete: bool
    """Whether the whole region was recovered. False means do not rely on this."""

    reason: str | None = None
    """Why the reading is incomplete, in officer-facing language."""


def tesseract_path() -> str | None:
    """Return the Tesseract binary, or None if this deployment has none.

    Returns:
        The resolved path, or None. None is a normal state, not an error.
    """
    return shutil.which("tesseract")


def read_mrz(image: Any) -> TextReading:  # noqa: ANN401 - a NumPy array; core stays free of NumPy
    """Read a machine-readable strip crop with a character-set restricted reader.

    Args:
        image: The strip crop, as a BGR array.

    Returns:
        The recovered lines. When no suitable reader is installed the result is
        empty and incomplete, with a reason an officer can read. It never
        returns a guess.
    """
    binary = tesseract_path()
    if binary is None:
        return TextReading((), complete=False, reason=TESSERACT_MISSING)

    try:
        import cv2

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "zone.png"
            cv2.imwrite(str(source), image)
            completed = subprocess.run(  # noqa: S603 - fixed argument list, no shell
                [
                    binary,
                    str(source),
                    "stdout",
                    "--psm",
                    "6",
                    "-c",
                    f"tessedit_char_whitelist={MRZ_ALPHABET}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
    except Exception:  # extraction failing is a reported state, never a crash
        return TextReading((), complete=False, reason=TESSERACT_MISSING)

    lines = tuple(
        line.strip().replace(" ", "") for line in completed.stdout.splitlines() if line.strip()
    )
    if not lines:
        return TextReading((), complete=False, reason=TESSERACT_MISSING)
    return TextReading(lines, complete=True)


def read_printed_text(image: Any) -> TextReading:  # noqa: ANN401 - a NumPy array
    """Read the printed page with the general text recogniser.

    Args:
        image: The page, as a BGR array.

    Returns:
        The recovered lines. Reliable enough for the printed page, and not used
        for the strip; see the module docstring.
    """
    try:
        from rapidocr_onnxruntime import RapidOCR

        engine = RapidOCR()
        detected, _elapsed = engine(image)
    except Exception:  # extraction failing is a reported state, never a crash
        return TextReading((), complete=False, reason=RAPIDOCR_MISSING)

    lines = tuple(str(entry[1]).strip() for entry in (detected or []) if str(entry[1]).strip())
    return TextReading(lines, complete=bool(lines), reason=None if lines else RAPIDOCR_MISSING)
