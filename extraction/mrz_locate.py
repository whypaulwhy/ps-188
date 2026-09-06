"""Finding the machine-readable strip on a document image.

The strip is a dense band of dark characters on a light ground, wider than it
is tall, near the bottom of the document. That description is enough to find it
with morphology alone, which is worth preferring over a learned locator: a
deterministic step here keeps the uncertainty concentrated in the readers,
where it is measured.

Returning None means no band that looks like a strip was found. That is not a
finding about the document — plenty of documents in scope have no strip at all
— and the caller reports it as a check that could not be made.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

MIN_ASPECT: Final[float] = 4.0
"""A strip is much wider than it is tall. Below this, it is something else."""

MIN_WIDTH_FRACTION: Final[float] = 0.55
"""A strip spans most of the document's width."""

SEARCH_FROM: Final[float] = 0.45
"""Only the lower part of the document is searched, where a strip is printed."""

DENSITY_THRESHOLD: Final[float] = 0.12
"""A strip row is far denser than a row of printed fields.

Calibrated by measurement rather than chosen: on this project's synthetic
specimens the strip rows measure 0.15 to 0.26 and the printed field rows
reach 0.05, so this sits in the gap between them.

**It is tuned to synthetic data.** Real captures vary in lighting, print
contrast and resolution, and this constant is the first thing to
re-measure against them. Until that happens, a strip this misses is
reported as a strip that could not be read, which is the safe direction.
"""

MAX_LINE_GAP: Final[int] = 40
"""Rows this close are one band, so the two strip lines are found together."""

MIN_BAND_HEIGHT: Final[float] = 0.02
"""A strip is two lines of characters tall. Anything thinner is a printed rule."""

DENSITY_CEILING: Final[float] = 0.85
"""A solid line is almost entirely ink; text never is. This tells them apart."""


@dataclass(frozen=True)
class MrzRegion:
    """Where the strip was found, in pixels from the top left."""

    left: int
    top: int
    right: int
    bottom: int

    def crop(self, image: Any, pad: int = 8) -> Any:  # noqa: ANN401 - a NumPy array
        """Return the strip region, with a little padding around it."""
        height, width = image.shape[:2]
        return image[
            max(0, self.top - pad) : min(height, self.bottom + pad),
            max(0, self.left - pad) : min(width, self.right + pad),
        ]


def locate_mrz(image: Any) -> MrzRegion | None:  # noqa: ANN401 - a NumPy array
    """Locate the machine-readable strip in a normalised document image.

    Works from a row-density profile rather than from contours. Contours are
    the usual recipe and they fail here for a reason worth recording: a
    document has a printed border, and morphological closing bridges the strip
    to that border, so the whole card comes back as one blob. Ink density per
    row has no such failure mode — the strip is denser than any other band on
    the document because it is an unbroken run of characters.

    Args:
        image: A single-channel array, as returned by
            :func:`extraction.preprocess.normalise`.

    Returns:
        The region, or None if no band resembling a strip was found.
    """
    import cv2
    import numpy as np

    height, width = image.shape[:2]
    blackhat = cv2.morphologyEx(
        cv2.GaussianBlur(image, (3, 3), 0),
        cv2.MORPH_BLACKHAT,
        cv2.getStructuringElement(cv2.MORPH_RECT, (21, 5)),
    )
    _threshold, binary = cv2.threshold(blackhat, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)

    # Ignore a margin, so the printed border of the document is not counted as ink.
    margin = max(2, int(width * 0.02))
    inner = binary[:, margin : width - margin]
    density = (inner > 0).sum(axis=1) / inner.shape[1]

    start = int(height * SEARCH_FROM)
    dense = density >= DENSITY_THRESHOLD
    dense[:start] = False
    if not dense.any():
        return None

    # Group contiguous dense rows, bridging the gap between the two strip lines.
    rows = np.flatnonzero(dense)
    bands: list[list[int]] = [[int(rows[0]), int(rows[0])]]
    for row in rows[1:]:
        if int(row) - bands[-1][1] <= MAX_LINE_GAP:
            bands[-1][1] = int(row)
        else:
            bands.append([int(row), int(row)])

    best: MrzRegion | None = None
    best_ink = 0.0
    for top, bottom in bands:
        band = inner[top : bottom + 1]
        columns = np.flatnonzero((band > 0).any(axis=0))
        if columns.size == 0:
            continue
        left, right = int(columns[0]) + margin, int(columns[-1]) + margin
        span, tall = right - left, bottom - top + 1
        if span < width * MIN_WIDTH_FRACTION or span / tall < MIN_ASPECT:
            continue
        if tall < height * MIN_BAND_HEIGHT:
            continue
        ink = float((band > 0).sum())
        if ink / band.size > DENSITY_CEILING:
            # A printed rule, not text. The border of a card is exactly this.
            continue
        if ink > best_ink:
            best_ink = ink
            best = MrzRegion(left, top, right, bottom + 1)
    return best
