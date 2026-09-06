"""Rung 2 detector: TruFor tamper localisation.

The only module in this project permitted to import PyTorch, and it does so
lazily so that a deployment without it starts normally.

**It currently reports `INCONCLUSIVE` on every document**, because there are no
TruFor weights available here and PyTorch is not installed. That is the
specified behaviour rather than a gap papered over: CLAUDE.md's testing rule
asks a Rung 2 detector for `INCONCLUSIVE` when its model is unavailable, and the
honesty rule requires the officer to be told the model did not load rather than
shown a clean result.

Installing PyTorch without weights would buy an import that still cannot score
anything, so it has not been installed. See ADR 0002 for why inference is ONNX
Runtime everywhere except here.

To enable it: set `SENTINELID_TRUFOR_WEIGHTS` to a weights file and install
PyTorch CPU. Anything else — a missing file, a missing package, a load failure —
lands on the same honest inconclusive path.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "trufor/unavailable"
WEIGHTS_ENV: Final[str] = "SENTINELID_TRUFOR_WEIGHTS"
IMAGE_MEDIA_PREFIX: Final[str] = "image/"

MODEL_UNAVAILABLE: Final[str] = (
    "The alteration detection model is not installed at this checkpoint, so this "
    "check was not made. Nothing about the document was established either way."
)


def weights_path() -> Path | None:
    """Return the configured TruFor weights, or None if there are none.

    Returns:
        The weights file, or None. None is a normal state here.
    """
    configured = os.environ.get(WEIGHTS_ENV)
    if not configured:
        return None
    candidate = Path(configured)
    return candidate if candidate.is_file() else None


def torch_available() -> bool:
    """Report whether PyTorch can be imported, without importing it at module load.

    Returns:
        Whether the import succeeds.
    """
    try:
        import torch  # noqa: F401
    except Exception:
        return False
    return True


@register
class TruForTamperDetector(Detector):
    """Learned tamper localisation. Reports inconclusive when its model is absent."""

    id = "rung2.tamper_trufor"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether the subject carries an image."""
        return any(
            artefact.media_type.startswith(IMAGE_MEDIA_PREFIX) for artefact in subject.artefacts
        )

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Report a result. Currently always inconclusive; see the module docstring."""
        started = time.perf_counter()
        artefact = next(
            (a for a in subject.artefacts if a.media_type.startswith(IMAGE_MEDIA_PREFIX)), None
        )
        if artefact is None:  # pragma: no cover - guarded by applies_to
            return ()

        # Both conditions must hold before this detector can say anything at all.
        # Neither is met in this deployment, and saying so out loud is the point.
        if weights_path() is None or not torch_available():
            return (
                Evidence(
                    detector_id=self.id,
                    rung=self.rung,
                    result=Result.INCONCLUSIVE,
                    reasons=(MODEL_UNAVAILABLE,),
                    runtime_ms=(time.perf_counter() - started) * 1000,
                    model_version=DETECTOR_VERSION,
                    input_digest=artefact.sha256,
                ),
            )

        msg = (
            "TruFor inference is not written: no weights have ever been available "
            "to develop it against. See the module docstring."
        )
        raise NotImplementedError(msg)


def build() -> Detector:
    """Construct the TruFor tamper localisation detector."""
    return TruForTamperDetector()
