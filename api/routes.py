"""The HTTP surface: submit a capture, read a case, record a review, prove a log.

Every screening response carries what was **not** checked and the rendered
officer text, because a JSON body handed to a client is a report, and CLAUDE.md
makes no exception for reports that happen to be machine-readable.

Three refusals worth naming, since each is a place where returning something
would be worse than returning nothing:

* **No signing key, no checkpoint.** `/ledger/checkpoint` returns 503 rather
  than signing with a key generated at start-up. A signature nobody can check
  against a published key looks exactly like proof and is not.
* **A note containing a document number is rejected, not truncated.** The
  officer is told what to remove. Silently stripping it would leave a review
  whose reasoning had been edited by a regular expression.
* **An unreadable capture is screened anyway.** It is not a 400. The case gets
  a verdict of `MANUAL_REVIEW` saying nothing could be read, is recorded, and
  reaches an officer — a border that drops malformed input has a gap in it.
"""

from __future__ import annotations

import datetime
import hashlib

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import Context, get_context, get_session, new_case_id
from api.schemas import (
    CheckpointOut,
    HealthOut,
    ProofOut,
    ReviewIn,
    ScreeningOut,
    screening_out,
)
from api.screening import assemble, screen
from core.contracts import DocumentType, OfficerReview, Provenance
from db.guards import RawIdentifierError
from db.models import CaseRecord, LedgerLeaf
from db.recording import RecordingError, load_case, load_log, recent_cases, record_review
from db.recording import record_screening as store_screening
from explain.renderer import render_verdict
from ledger.hashchain import verify_checkpoint

router = APIRouter()

NOTE_HOLDS_A_NUMBER = (
    "This note appears to contain a document number. Remove it and describe the "
    "document instead: numbers are stored only as digests, never in the clear."
)
CAPTURE_TOO_LARGE = "This capture is larger than this checkpoint accepts."
NO_SIGNING_KEY = (
    "This checkpoint holds no signing key, so no checkpoint can be published. "
    "No unsigned substitute is offered, because one would look like proof."
)


def _now() -> datetime.datetime:
    """Return the current instant. One clock read per request, in one place."""
    return datetime.datetime.now(datetime.UTC)


@router.get("/health", response_model=HealthOut)
def health(
    context: Context = Depends(get_context),
    session: Session = Depends(get_session),
) -> HealthOut:
    """Report what this deployment can do, and what it cannot.

    The `unavailable` list is the point of this endpoint. A health check that
    only ever says "ok" cannot tell an operator that their signing key has not
    been mounted for three weeks.
    """
    return HealthOut(
        checkpoint_id=context.settings.checkpoint_id,
        detectors=tuple(detector.id for detector in assemble(context.deployment)),
        unavailable=context.settings.unavailable(),
        cases_recorded=session.execute(select(func.count()).select_from(CaseRecord)).scalar_one(),
        ledger_entries=session.execute(select(func.count()).select_from(LedgerLeaf)).scalar_one(),
    )


@router.post("/screenings", response_model=ScreeningOut, status_code=status.HTTP_201_CREATED)
async def submit_screening(
    capture: UploadFile = File(..., description="The document image or file, as captured."),
    declared_type: str = Form(
        DocumentType.UNRECOGNISED.value, description="What the document claims to be."
    ),
    context: Context = Depends(get_context),
    session: Session = Depends(get_session),
) -> ScreeningOut:
    """Screen one capture, record it, and return the officer-facing result."""
    payload = await capture.read()
    if len(payload) > context.settings.max_upload_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, CAPTURE_TOO_LARGE)

    try:
        document_type = DocumentType(declared_type)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"{declared_type!r} is not a document type"
        ) from error

    now = _now()
    case_id = new_case_id(now=now)
    provenance = Provenance(
        source_id=case_id,
        sha256=hashlib.sha256(payload).hexdigest(),
        media_type=capture.content_type or "application/octet-stream",
        byte_size=len(payload),
        captured_at=now,
        received_at=now,
        checkpoint_id=context.settings.checkpoint_id,
    )

    subject, verdict = screen(
        payload,
        provenance=provenance,
        deployment=context.deployment,
        decided_at=now,
        declared_type=document_type,
    )
    try:
        store_screening(
            session,
            case_id=case_id,
            verdict=verdict,
            checkpoint_id=context.settings.checkpoint_id,
            recorded_at=now,
        )
    except RecordingError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error

    view = load_case(session, case_id)
    if view is None:  # pragma: no cover - the write above just succeeded
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "the case was not stored")
    return screening_out(
        view, report=render_verdict(view.verdict), not_extracted=subject.not_extracted
    )


@router.get("/cases", response_model=list[ScreeningOut])
def list_cases(
    limit: int = 50,
    session: Session = Depends(get_session),
) -> list[ScreeningOut]:
    """Return recent cases, newest first."""
    return [
        screening_out(view, report=render_verdict(view.verdict))
        for view in recent_cases(session, limit=limit)
    ]


@router.get("/cases/{case_id}", response_model=ScreeningOut)
def read_case(case_id: str, session: Session = Depends(get_session)) -> ScreeningOut:
    """Return one case, with every review recorded against it."""
    view = load_case(session, case_id)
    if view is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no case {case_id!r}")
    return screening_out(view, report=render_verdict(view.verdict))


@router.get("/cases/{case_id}/report", response_class=PlainTextResponse)
def read_report(case_id: str, session: Session = Depends(get_session)) -> str:
    """Return the officer-facing report for one case as plain text."""
    view = load_case(session, case_id)
    if view is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no case {case_id!r}")
    return render_verdict(view.verdict)


@router.post(
    "/cases/{case_id}/reviews",
    response_model=ScreeningOut,
    status_code=status.HTTP_201_CREATED,
)
def submit_review(
    case_id: str,
    submitted: ReviewIn,
    session: Session = Depends(get_session),
) -> ScreeningOut:
    """Record an officer's decision on a case.

    The verdict is not touched. A review is a new record and a new ledger entry,
    so the log holds what happened to the case in order rather than only its
    latest state.
    """
    view = load_case(session, case_id)
    if view is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no case {case_id!r}")

    try:
        review = OfficerReview(
            case_id=case_id,
            outcome=submitted.outcome,
            officer_id=submitted.officer_id,
            note=submitted.note,
            system_decision=view.verdict.decision,
            recorded_at=_now(),
        )
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error

    try:
        record_review(session, review)
    except RawIdentifierError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, NOTE_HOLDS_A_NUMBER) from error
    except RecordingError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error

    updated = load_case(session, case_id)
    if updated is None:  # pragma: no cover - the case was read above
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no case {case_id!r}")
    return screening_out(updated, report=render_verdict(updated.verdict))


@router.get("/ledger/checkpoint", response_model=CheckpointOut)
def ledger_checkpoint(
    context: Context = Depends(get_context),
    session: Session = Depends(get_session),
) -> CheckpointOut:
    """Sign and return a statement about the log's current state."""
    key = context.settings.ledger_key
    if key is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, NO_SIGNING_KEY)

    log = load_log(session)
    signed = log.checkpoint(key=key, signed_at=_now())
    public = key.public_key()
    if not verify_checkpoint(signed, key=public):  # pragma: no cover - it was just signed
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "the signed checkpoint did not verify"
        )
    return CheckpointOut(
        tree_size=signed.tree_size,
        root=signed.root.hex(),
        signed_at=signed.signed_at,
        signature=signed.signature.hex(),
        public_key=public.public_bytes_raw().hex(),
    )


@router.get("/ledger/proof/{leaf_index}", response_model=ProofOut)
def ledger_proof(leaf_index: int, session: Session = Depends(get_session)) -> ProofOut:
    """Return an inclusion proof for one log entry."""
    log = load_log(session)
    if not 0 <= leaf_index < len(log):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no log entry at {leaf_index}")
    return ProofOut(
        leaf_index=leaf_index,
        leaf=log.leaf(leaf_index).hex(),
        tree_size=len(log),
        proof=tuple(sibling.hex() for sibling in log.proof(leaf_index)),
        root=log.root().hex(),
    )


def build_router() -> APIRouter:
    """Return the assembled router.

    Returns:
        The router, so the application factory does not import module state.
    """
    return router
