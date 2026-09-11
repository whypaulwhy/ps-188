"""Rung 2 detector: does the document portrait match the person presenting it?

The attack this answers is the one every other rung is blind to. A genuine,
correctly signed, unexpired document presented by someone who is not its holder
passes every cryptographic and deterministic check there is. Only a comparison
between the portrait and the bearer notices, and that comparison is inference.

**It can only escalate.** A face comparison never clears a document and never
rejects one. `score` is suspicion — a larger number means the faces look *less*
alike — so it can only move a case toward a human.

**The threshold here is not calibrated, and that is stated rather than hidden.**
`SUSPICION_THRESHOLD` is a placeholder. Calibrating it needs a corpus of real
faces, and obtaining one is a question of lawful basis and consent before it is
a question of data — `docs/scope.md` records the constraint and phase 7 records
why no synthetic faces are generated to stand in. No accuracy figure for this
detector exists anywhere in this repository, and rule 2 of `CLAUDE.md` means
none may be written until `eval/run_eval.py` produces one on a named dataset.

What makes shipping an uncalibrated threshold defensible is the rung: the worst
a badly chosen number can do here is send more cases to a person. It cannot
clear anybody, and it cannot reject anybody.

**Nothing here treats an embedding as anonymous.** An embedding is partially
invertible by model inversion. This detector computes two, compares them, and
drops them when the comparison ends: none is written to disk, put in the
evidence, or persisted. Anything that *did* want to keep one would take it
through :mod:`core.privacy.biometrics`, which encrypts it under a key separate
from the identifier hashing key and carries a retention window the code
enforces. See rule 4 of CLAUDE.md.
"""

from __future__ import annotations

import time
from typing import Final

from core.contracts import DOCUMENT_ROLE, LIVE_CAPTURE_ROLE, Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung2_inference import face_engine

DETECTOR_VERSION: Final[str] = "face_match/1.0.0+buffalo_l"

SUSPICION_THRESHOLD: Final[float] = 0.33
"""Above this the case is escalated. Equivalent to a similarity below +0.34.

**Uncalibrated**, and chosen to fail closed rather than to be right. It sits in
the region `buffalo_l`, an ArcFace recogniser, is conventionally operated in:
two pictures of one person well above it, two different people well below.
That is the model's published character, not a measurement made here.

A local check on the owner's own photographs and a handful of document
portraits, held outside the repository, was consistent with that - and showed
that the first value, 0.55, sat so low that different people would have read as
"consistent with the photograph". It was moved for that reason. **No rate from
that check is recorded here**, because rule 2 of CLAUDE.md admits only figures
produced by `eval/run_eval.py` on a named dataset, and that check was not one.
The false-escalation and missed-impostor rates for this threshold are **TBD**.
"""

MINIMUM_CONFIDENCE: Final[float] = 0.5
"""Below this the detector does not accept that it found a face at all.

A low-confidence detection compared against anything produces a number, and a
number that means nothing is worse here than no number, because it would be
read as a comparison that happened.
"""

MODEL_UNAVAILABLE: Final[str] = (
    "The face comparison model is not installed at this checkpoint, so the "
    "photograph on this document was not compared with the person presenting it. "
    "Nothing about who is holding this document was established."
)
NO_LIVE_CAPTURE: Final[str] = (
    "No photograph of the person presenting this document was taken, so there was "
    "nothing to compare the picture on it against."
)
NO_FACE_ON_DOCUMENT: Final[str] = (
    "No photograph of a face could be found on this document, so there was nothing "
    "to compare the person against. This is usually a problem with the scan."
)
NO_FACE_IN_CAPTURE: Final[str] = (
    "No face could be found in the photograph of the person presenting this "
    "document, so no comparison was made. Take the photograph again, with the "
    "person facing the camera."
)


def suspicion(similarity: float) -> float:
    """Turn a similarity into a suspicion score in [0, 1].

    Args:
        similarity: Cosine similarity of two face embeddings, in [-1, 1].
            Higher means more alike.

    Returns:
        Suspicion. A larger number means the faces look *less* alike, because
        every Rung 2 score in this system points the same way: toward a human.
    """
    return min(1.0, max(0.0, (1.0 - similarity) / 2.0))


@register
class FaceMatchDetector(Detector):
    """Compares the document portrait with a live capture of the bearer."""

    id = "rung2.face_match"
    rung = Rung.INFERENCE

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Returns true even when there is no live capture, so that the officer is
        told the bearer was not checked rather than being shown nothing at all.
        A document that was never compared against its holder is a materially
        different case from one that was.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Compare the portrait with the live capture, or say why it could not."""
        started = time.perf_counter()
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256
        result, score, reasons = self._examine(subject)
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                score=score,
                uncertainty=None if score is None else 1.0,
                reasons=reasons,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )

    def _examine(self, subject: Subject) -> tuple[Result, float | None, tuple[str, ...]]:
        """Decide the result, the score and the officer-facing reasons."""
        if not face_engine.available():
            return Result.INCONCLUSIVE, None, (MODEL_UNAVAILABLE,)

        live = subject.artefact(LIVE_CAPTURE_ROLE)
        if live is None:
            return Result.INCONCLUSIVE, None, (NO_LIVE_CAPTURE,)

        document = subject.artefact(DOCUMENT_ROLE)
        if document is None:
            return Result.INCONCLUSIVE, None, (NO_FACE_ON_DOCUMENT,)

        on_document = self._best(document.data)
        if on_document is None:
            return Result.INCONCLUSIVE, None, (NO_FACE_ON_DOCUMENT,)

        in_person = self._best(live.data)
        if in_person is None:
            return Result.INCONCLUSIVE, None, (NO_FACE_IN_CAPTURE,)

        score = suspicion(face_engine.similarity(on_document, in_person))
        if score >= SUSPICION_THRESHOLD:
            return (
                Result.SUSPICIOUS,
                score,
                (
                    "The face of the person presenting this document does not look "
                    "like the photograph on it.",
                    "This is a machine's impression, not proof. Lighting, age and a "
                    "poor photograph all cause it. A person should compare them.",
                ),
            )
        return (
            Result.NO_FINDING,
            score,
            (
                "The face of the person presenting this document is consistent with "
                "the photograph on it.",
                "This is not proof that they are the same person, and it establishes "
                "nothing about whether the document itself is genuine.",
            ),
        )

    def _best(self, image: bytes) -> face_engine.DetectedFace | None:
        """Return the largest confidently detected face in an image, if any."""
        for face in face_engine.faces(image):
            if face.confidence >= MINIMUM_CONFIDENCE:
                return face
        return None


def build() -> Detector:
    """Construct the face similarity detector."""
    return FaceMatchDetector()
