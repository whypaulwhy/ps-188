"""Decoding QR and barcode payloads from a document image.

The payload bytes matter exactly: a Rung 0 signature is computed over them, so
nothing here normalises, strips or re-encodes what it finds.

A document with no code is the ordinary case on these borders and returns an
empty result rather than an error. A decoder that is not installed is a
different thing, and says so.
"""

from __future__ import annotations

from typing import Any, Final

DECODER_MISSING: Final[str] = (
    "The code on this document could not be read, because the code reader is "
    "not available at this checkpoint."
)


def decoder_available() -> bool:
    """Report whether a code reader can be loaded at all.

    On Windows the reader is a bundled native library that needs the Microsoft
    Visual C++ runtime; without it the import fails and no code can be decoded
    anywhere on the machine. That is a deployment fact worth being able to ask
    about directly, rather than inferring it from a failed decode.

    Returns:
        Whether the decoder loads. False is a normal state, not an error.
    """
    try:
        from pyzbar import pyzbar  # noqa: F401
    except Exception:
        return False
    return True


def decode_qr(image: Any) -> tuple[list[bytes], str | None]:  # noqa: ANN401 - a NumPy array
    """Decode every code found in an image.

    Args:
        image: The document, as an array or a PIL image.

    Returns:
        The decoded payloads, and a reason when the decoder itself was
        unavailable. An empty list with no reason means the document carries no
        code, which is not a failure.
    """
    try:
        from pyzbar import pyzbar

        return [symbol.data for symbol in pyzbar.decode(image)], None
    except Exception:  # a missing decoder is a reported state, never a crash
        return [], DECODER_MISSING
