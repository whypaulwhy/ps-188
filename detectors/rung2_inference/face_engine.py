"""Loading the face models, once, and describing what they found.

Shared by `face_match` and `pad_liveness` so there is one answer to "are the
models here" and one place that decodes an image into faces. Two detectors each
loading their own copy of a 166 MB recogniser would double the memory a
checkpoint needs and could disagree about what a face is.

**Everything is optional and absence is the normal state.** Nothing here is
imported until a detector asks for it, and every entry point returns `None` or
an empty result rather than raising when the models are not installed. A
deployment without them screens documents perfectly well and says on every case
that the bearer was not checked.

**On the models.** InsightFace `buffalo_l` through ONNX Runtime, which is what
`CLAUDE.md` specifies. Detection is SCRFD and recognition is ArcFace; the
package owns that arithmetic rather than this repository re-deriving anchor
decoding, which is the kind of code that is wrong in a way nothing notices.

**Rule 4 applies to everything this module returns.** An embedding is a
partially invertible representation of a face, never an anonymous one. Nothing
here writes one anywhere: they are computed, compared, and dropped when the
comparison ends. A caller that wants to *persist* one must take it through
`core.privacy.biometrics`, which encrypts it and carries a retention window.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

MODEL_ROOT_ENV: Final[str] = "SENTINELID_FACE_MODEL_ROOT"
"""Directory holding `models/buffalo_l/`. Absent means the models are absent."""

MODEL_PACK: Final[str] = "buffalo_l"
DETECTION_SIZE: Final[tuple[int, int]] = (640, 640)
"""What the detector is given. Larger finds smaller faces and costs more time."""

_LOCK: Final[threading.Lock] = threading.Lock()
_ANALYSER: list[Any] = []
"""A one-slot cache. Loading the recogniser takes seconds and megabytes."""


@dataclass(frozen=True)
class DetectedFace:
    """One face found in one image."""

    box: tuple[float, float, float, float]
    """Left, top, right, bottom, in pixels."""

    confidence: float
    """How sure the detector is that this is a face at all."""

    keypoints: tuple[tuple[float, float], ...]
    """Five points: both eyes, the nose, both mouth corners."""

    embedding: tuple[float, ...]
    """The recogniser's representation of this face.

    **Not anonymous.** It is partially invertible by model inversion, which is
    why it is never written anywhere by this module and why persisting one is
    `core.privacy.biometrics`'s job rather than a caller's convenience.
    """

    @property
    def area(self) -> float:
        """Pixel area of the face box, used to pick the subject of a photograph."""
        left, top, right, bottom = self.box
        return max(0.0, right - left) * max(0.0, bottom - top)


def model_root() -> Path | None:
    """Return the configured model directory, or None if there is none.

    Returns:
        The directory, or None. None is the normal state of a deployment that
        has not been given the face models.
    """
    configured = os.environ.get(MODEL_ROOT_ENV, "").strip()
    if not configured:
        return None
    root = Path(configured)
    return root if (root / "models" / MODEL_PACK).is_dir() else None


def available() -> bool:
    """Report whether face comparison can run at all.

    Returns:
        Whether both a model directory and the runtime are present. Checked
        without importing anything heavy, so a screening on a deployment
        without the models costs nothing.
    """
    return model_root() is not None


def _load() -> Any | None:  # noqa: ANN401 - an InsightFace FaceAnalysis
    """Load the models once, or return None if they cannot be loaded."""
    if _ANALYSER:
        return _ANALYSER[0]

    root = model_root()
    if root is None:
        return None

    with _LOCK:
        if _ANALYSER:
            return _ANALYSER[0]
        try:
            # Imported here, not at module scope: a deployment without the
            # models must not pay for the import, and must not fail because of
            # it either.
            from insightface.app import FaceAnalysis

            analyser = FaceAnalysis(
                name=MODEL_PACK,
                root=str(root),
                providers=["CPUExecutionProvider"],
                allowed_modules=["detection", "recognition"],
            )
            analyser.prepare(ctx_id=-1, det_size=DETECTION_SIZE)
        except Exception:
            # Deliberately broad. A missing package, a corrupt model file and an
            # incompatible runtime are all the same thing to a detector: it
            # cannot run, and it must say so rather than take the case down.
            return None
        _ANALYSER.append(analyser)
        return analyser


def faces(image: bytes) -> tuple[DetectedFace, ...]:
    """Find every face in an image.

    Args:
        image: The encoded image, exactly as captured.

    Returns:
        The faces found, largest first. Empty when the models are unavailable,
        the bytes are not an image, or there is simply no face in it — three
        different situations a caller must not conflate, which is why the
        caller checks :func:`available` separately.
    """
    analyser = _load()
    if analyser is None:
        return ()

    try:
        import cv2
        import numpy as np

        decoded = cv2.imdecode(np.frombuffer(image, np.uint8), cv2.IMREAD_COLOR)
        if decoded is None:
            return ()
        found = analyser.get(decoded)
    except Exception:
        return ()

    detected: list[DetectedFace] = []
    for face in found:
        embedding = getattr(face, "normed_embedding", None)
        if embedding is None:
            continue
        box = tuple(float(value) for value in face.bbox[:4])
        keypoints = tuple((float(point[0]), float(point[1])) for point in getattr(face, "kps", ()))
        detected.append(
            DetectedFace(
                box=(box[0], box[1], box[2], box[3]),
                confidence=float(getattr(face, "det_score", 0.0)),
                keypoints=keypoints,
                embedding=tuple(float(value) for value in embedding),
            )
        )
    return tuple(sorted(detected, key=lambda item: item.area, reverse=True))


def similarity(left: DetectedFace, right: DetectedFace) -> float:
    """Return how alike two faces are, between -1 and 1.

    Args:
        left: One face.
        right: The other.

    Returns:
        The cosine similarity of their embeddings. Higher means more alike.
        The embeddings are already normalised, so this is their dot product.
    """
    return float(sum(a * b for a, b in zip(left.embedding, right.embedding, strict=True)))


def reset_cache() -> None:
    """Drop the loaded models. For tests that change the configured root."""
    with _LOCK:
        _ANALYSER.clear()
