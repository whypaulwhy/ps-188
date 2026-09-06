"""Turning captured bytes into an array a detector's helpers can work on.

Normalisation only. Nothing here decides anything, and nothing here repairs a
document: a crooked or dark capture is straightened and levelled so the rest of
extraction has a fair chance, but no pixel is invented and no field is guessed.

The digest recorded on evidence is always of the bytes **as received**, never
of the normalised array, so an audit can tell whether a detector saw the
original capture or something derived from it.
"""

from __future__ import annotations

from typing import Any


def decode(png: bytes) -> Any:  # noqa: ANN401 - a NumPy array; core stays free of NumPy
    """Decode captured bytes into a BGR array.

    Args:
        png: The captured image, in any format OpenCV can read.

    Returns:
        The decoded array.

    Raises:
        ValueError: If the bytes are not a readable image.
    """
    import cv2
    import numpy as np

    array = cv2.imdecode(np.frombuffer(png, dtype=np.uint8), cv2.IMREAD_COLOR)
    if array is None:
        msg = "the captured bytes are not a readable image"
        raise ValueError(msg)
    return array


def normalise(image: Any) -> Any:  # noqa: ANN401 - a NumPy array
    """Return a levelled greyscale copy of a captured document image.

    Args:
        image: The decoded BGR array.

    Returns:
        A single-channel array with its contrast equalised, which is what the
        strip locator and the readers work on.
    """
    import cv2

    grey = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    return cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(grey)
