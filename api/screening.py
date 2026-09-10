"""Running every check that can run, and saying so when one cannot.

The detectors are pure functions over a `Subject`; this is the code that
decides which of them exist in this deployment, hands each what it needs, and
turns the results into a verdict. It lives in `api/` because assembling a
detector needs deployment material — a trust store, a hashing key, a watchlist
— and rule 5 of CLAUDE.md keeps that knowledge out of `detectors/`.

**A detector that raises is reported, not dropped.** Wrapping the whole loop in
one `try` and returning a partial result would be silence about a check that
did not happen, which CLAUDE.md calls a defect. Each detector is run
individually, and one that fails contributes evidence at its own rung saying it
could not be completed. Every such result belongs to the ladder's `SILENT` set,
so it lands in `Verdict.not_checked`, in front of the officer, and it can
neither clear nor reject a case.

**Nothing is skipped silently either.** `assemble` covers every detector in the
registry, and a test fails if one is registered but never assembled. A detector
that exists and never runs is the same defect wearing different clothes.
"""

from __future__ import annotations

import dataclasses
import datetime
import time

from api.settings import Settings
from core.contracts import (
    DocumentType,
    Evidence,
    Provenance,
    Result,
    Rung,
    Subject,
    Verdict,
)
from core.trust.ladder import resolve
from detectors.base import Detector
from detectors.rung0_crypto import digilocker_xml_sig, pdf_pkcs7, signed_qr
from detectors.rung0_crypto.trust_store import TrustStore
from detectors.rung1_deterministic import (
    aadhaar_number,
    expiry,
    field_crossmatch,
    mrz_checkdigits,
)
from detectors.rung2_inference import (
    face_match,
    metadata_forensics,
    pad_liveness,
    pdf_structure,
    tamper_classical,
    tamper_trufor,
)
from detectors.rung3_context import repeat_identity, watchlist
from detectors.rung3_context.context_store import CrossingHistory, Watchlist
from extraction.pipeline import build_subject

FAILURE_RESULTS: dict[Rung, Result] = {
    Rung.CRYPTOGRAPHIC: Result.NO_PROOF_PRESENT,
    Rung.DETERMINISTIC: Result.NOT_APPLICABLE,
    Rung.INFERENCE: Result.INCONCLUSIVE,
    Rung.CONTEXTUAL: Result.NOT_CHECKED,
}
"""What a detector that could not run reports, per rung. All four are `SILENT`."""

FAILURE_REF: str = "SENTINEL ID CLAUDE.md rule 1: uncertainty routes to MANUAL_REVIEW"
"""Cited when a Rung 0 or 1 detector fails.

The contract requires those rungs to cite the clause that makes their output
defensible. A check that did not run applied no clause of ICAO or UIDAI, and
naming one would be a false citation. What makes "nothing was established here"
defensible is the fail-closed rule itself, so that is what it cites.
"""

FAILURE_VERSION: str = "did-not-run"
"""Recorded as the model version, so the audit trail shows nothing produced this."""


@dataclasses.dataclass(frozen=True)
class Deployment:
    """The material a screening needs that does not come from the capture.

    Assembled once at start-up and handed to every screening. Empty is a valid
    state for all three collections and means the corresponding check finds
    nothing rather than not running — an empty trust store, for instance, means
    no document can be cleared, which is correct for a deployment that has not
    been given real issuer keys.
    """

    settings: Settings
    trust_store: TrustStore = dataclasses.field(default_factory=TrustStore)
    history: CrossingHistory = dataclasses.field(default_factory=CrossingHistory)
    watchlist: Watchlist = dataclasses.field(default_factory=Watchlist)


def assemble(deployment: Deployment) -> tuple[Detector, ...]:
    """Build every detector this deployment can run.

    Args:
        deployment: The deployment's trust store, context and settings.

    Returns:
        The detectors, in rung order. Rung 3 is present only when a hashing key
        is configured, because a contextual check without one cannot identify a
        document at all; :meth:`Settings.unavailable` is what tells the officer
        so.
    """
    detectors: list[Detector] = [
        digilocker_xml_sig.build(deployment.trust_store),
        pdf_pkcs7.build(deployment.trust_store),
        signed_qr.build(deployment.trust_store),
        mrz_checkdigits.build(),
        expiry.build(),
        aadhaar_number.build(),
        field_crossmatch.build(),
        tamper_classical.build(),
        tamper_trufor.build(),
        metadata_forensics.build(),
        pdf_structure.build(),
        face_match.build(),
        pad_liveness.build(),
    ]
    if deployment.settings.hash_key is not None:
        key = deployment.settings.hash_key
        detectors.append(repeat_identity.build(deployment.history, key=key))
        detectors.append(watchlist.build(deployment.watchlist, key=key))
    return tuple(detectors)


def _could_not_run(detector: Detector, *, subject: Subject, elapsed_ms: float) -> Evidence:
    """Return evidence that a detector failed, at its own rung.

    The exception is deliberately not quoted to the officer. A traceback is not
    officer-facing text, and an exception message can carry data read off the
    document. The audit record says which check did not complete; the log is
    where an engineer looks for why.
    """
    rung = detector.rung
    return Evidence(
        detector_id=detector.id,
        rung=rung,
        result=FAILURE_RESULTS[rung],
        reasons=(
            "One of the automated checks could not be completed on this document, "
            "so it established nothing either way.",
        ),
        standard_ref=FAILURE_REF if rung in (Rung.CRYPTOGRAPHIC, Rung.DETERMINISTIC) else None,
        runtime_ms=elapsed_ms,
        model_version=FAILURE_VERSION,
        input_digest=subject.provenance.sha256,
    )


def run_detectors(detectors: tuple[Detector, ...], subject: Subject) -> tuple[Evidence, ...]:
    """Run each detector that applies, converting a failure into honest evidence.

    Args:
        detectors: The assembled detectors.
        subject: The material under examination.

    Returns:
        Every piece of evidence produced, in detector order.
    """
    collected: list[Evidence] = []
    for detector in detectors:
        started = time.perf_counter()
        try:
            if not detector.applies_to(subject):
                continue
            collected.extend(detector.run(subject))
        except Exception:  # A broken detector must not stop a crossing.
            elapsed = (time.perf_counter() - started) * 1000.0
            collected.append(_could_not_run(detector, subject=subject, elapsed_ms=elapsed))
    return tuple(collected)


def screen(
    captured: bytes,
    *,
    provenance: Provenance,
    deployment: Deployment,
    decided_at: datetime.datetime,
    declared_type: DocumentType = DocumentType.UNRECOGNISED,
) -> tuple[Subject, Verdict]:
    """Screen one capture and resolve it into a verdict.

    Args:
        captured: The image or document exactly as received.
        provenance: Where it came from and when.
        deployment: The deployment's detectors and context.
        decided_at: The instant stamped on the verdict, so every record of this
            case agrees about when it happened.
        declared_type: What the document claims to be, when that is known.

    Returns:
        The extracted subject and the verdict. Never raises on account of the
        capture: an unreadable file produces a subject with no zones, a stated
        reason, and a `MANUAL_REVIEW`.
    """
    subject = build_subject(captured, provenance=provenance, declared_type=declared_type)
    evidence = run_detectors(assemble(deployment), subject)
    verdict = resolve(evidence, provenance=provenance, decided_at=decided_at)
    return subject, _with_deployment_notices(verdict, deployment)


def _with_deployment_notices(verdict: Verdict, deployment: Deployment) -> Verdict:
    """Add what the deployment itself could not do to the unchecked list.

    A missing hashing key is not something a detector can report, because
    without one the detector was never built. It is still a check that did not
    happen, so it belongs in front of the officer with the others.
    """
    missing = deployment.settings.unavailable()
    if not missing:
        return verdict

    # Rebuilt through validation rather than `model_copy`, which skips it. A
    # verdict that reached storage without its validators having run would be
    # a verdict nothing had checked.
    return Verdict.model_validate(
        {**verdict.model_dump(), "not_checked": (*verdict.not_checked, *missing)}
    )
