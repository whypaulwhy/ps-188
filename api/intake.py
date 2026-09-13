"""Taking one capture in, screening it, and recording it.

Extracted from `api.routes` so that the JSON endpoint and the officer console's
upload form do the same thing. Two intake paths that drifted apart would mean a
document screened from the console and the same document screened over HTTP
could produce different records, which is the sort of difference nobody notices
until an audit.

**Nothing here decides anything.** It builds provenance, calls the screening
pipeline, and writes the result. The verdict comes from the trust ladder, the
same as it does for every other route.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib

from sqlalchemy.orm import Session

from api.screening import Deployment, screen
from api.settings import Settings
from core.contracts import ChallengeStep, DocumentType, Provenance, Subject, Verdict
from db.recording import record_screening

OCTET_STREAM: str = "application/octet-stream"
"""What a capture arriving without a stated media type is recorded as."""


@dataclasses.dataclass(frozen=True)
class Intake:
    """One recorded screening, as both surfaces need to see it."""

    case_id: str
    """The identifier the case was stored under."""

    subject: Subject
    """What extraction managed to read, including what it could not."""

    verdict: Verdict
    """What the ladder decided."""


def record_capture(
    session: Session,
    captured: bytes,
    *,
    case_id: str,
    settings: Settings,
    deployment: Deployment,
    now: datetime.datetime,
    media_type: str | None = None,
    declared_type: DocumentType = DocumentType.UNRECOGNISED,
    live_captures: tuple[tuple[bytes, str | None], ...] = (),
    liveness_challenge: tuple[ChallengeStep, ...] = (),
) -> Intake:
    """Screen one capture and record it, in the order every route must use.

    Args:
        session: An open session. The write is committed here.
        captured: The document exactly as received. Bytes that are not an image
            are not rejected: they produce a case with a stated reason, because
            a border that drops malformed input has a gap where someone would
            push.
        case_id: The identifier to store it under.
        settings: The deployment's configuration, for the checkpoint stamp.
        deployment: The assembled detectors.
        now: One clock read, shared by the provenance, the verdict and the
            ledger entry, so every record of this case agrees about when it
            happened.
        media_type: What the sender said the capture was, recorded as given.
        declared_type: What the document claims to be, when that is known.
        live_captures: Photographs of the person presenting the document, each
            with the media type the sender stated, in the order they were
            taken. They reach the face checks and are not stored; what is
            recorded is the verdict, exactly as for the document itself.
        liveness_challenge: What the person was asked to do while those
            photographs were taken. Empty when nothing was asked, which the
            challenge check reports rather than passing over.

    Returns:
        The case identifier, the subject and the verdict.

    Raises:
        RecordingError: If the case could not be written. Nothing partial
            survives.
    """
    provenance = Provenance(
        source_id=case_id,
        sha256=hashlib.sha256(captured).hexdigest(),
        media_type=media_type or OCTET_STREAM,
        byte_size=len(captured),
        captured_at=now,
        received_at=now,
        checkpoint_id=settings.checkpoint_id,
    )
    subject, verdict = screen(
        captured,
        provenance=provenance,
        deployment=deployment,
        decided_at=now,
        declared_type=declared_type,
        live_captures=tuple(
            (photograph, stated or OCTET_STREAM) for photograph, stated in live_captures
        ),
        liveness_challenge=liveness_challenge,
    )
    record_screening(
        session,
        case_id=case_id,
        verdict=verdict,
        checkpoint_id=settings.checkpoint_id,
        recorded_at=now,
    )
    return Intake(case_id=case_id, subject=subject, verdict=verdict)
