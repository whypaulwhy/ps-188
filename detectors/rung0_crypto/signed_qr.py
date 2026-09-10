"""Rung 0 detector: a signed identity code an issuing authority put on a card.

**This is not the Aadhaar Secure QR format.** That one is still a stub, and it
stays a stub until there is a real specimen to check a parser against —
`aadhaar_secure_qr.py` says why. What this module reads is a container defined
*by this project*, for an issuing authority that chooses to adopt it, so that
the path from a photographed card to a cryptographic clearance exists and can be
exercised end to end.

**What that is worth, and what it is not.** The cryptography is real: a genuine
RSA signature over exact bytes, checked against an anchor an operator installed
deliberately, through the same `verification.py` every other Rung 0 detector
uses. What it does not establish is that this system can read anybody else's
container. A format we define and then parse is, in that narrow sense, code
agreeing with itself. The value is in the surrounding machinery — anchors,
validity windows, algorithm allowlists, the ladder — all of which is format
independent and all of which a real container would reuse unchanged.

**The container.**

    SENTINELID-SQR1|<issuer id>|<algorithm>|<payload>|<signature>

where `payload` and `signature` are base64url without padding, and the signature
covers the payload bytes exactly as they decode — never the base64 text, and
never a re-serialisation of what the payload happens to contain. A container
that named its own algorithm and was believed would let a forger downgrade to a
weak one, so the algorithm here is a *claim*: the anchor decides whether it is
permitted, and an anchor that does not permit it refuses to verify at all.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import time
from dataclasses import dataclass
from typing import Final

from core.contracts import Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung0_crypto.trust_store import SignatureAlgorithm, TrustStore
from detectors.rung0_crypto.verification import VerificationOutcome, verify_detached

DETECTOR_VERSION: Final[str] = "signed_qr/1.0.0"
STANDARD_REF: Final[str] = (
    "SENTINEL ID signed identity code, container SENTINELID-SQR1 "
    "(RFC 4648 s.5 base64url, detached signature over the decoded payload)"
)

PREFIX: Final[str] = "SENTINELID-SQR1"
"""The container marker. A code not beginning with this is not ours to read."""

FIELDS: Final[int] = 5
"""Marker, issuer, algorithm, payload, signature."""

NO_CODE: Final[str] = (
    "This document carries no code that could hold an issuing authority's "
    "signature, so nothing about it could be confirmed by one."
)
NOT_OUR_CONTAINER: Final[str] = (
    "The code on this document is not a signed identity code this checkpoint "
    "knows how to read, so no signature could be checked. Nothing about the "
    "document was established either way."
)


@dataclass(frozen=True)
class SignedCode:
    """A container that parsed. Whether it verifies is a separate question."""

    issuer_id: str
    algorithm: SignatureAlgorithm
    payload: bytes
    signature: bytes


def _decode(chunk: str) -> bytes:
    """Decode one base64url field, tolerating the padding a writer may omit."""
    return base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4))


def parse_container(raw: bytes) -> SignedCode | None:
    """Read a signed identity code, or report that this is not one.

    Args:
        raw: The decoded bytes of a QR code, exactly as the reader produced them.

    Returns:
        The parsed container, or None if these bytes are not one. None is not a
        finding of forgery: most codes on most documents are not this format,
        and saying so is the honest answer.
    """
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None

    parts = text.split("|")
    if len(parts) != FIELDS or parts[0] != PREFIX:
        return None

    _, issuer_id, algorithm_name, payload_chunk, signature_chunk = parts
    if not issuer_id.strip():
        return None

    try:
        algorithm = SignatureAlgorithm(algorithm_name)
    except ValueError:
        return None

    try:
        payload = _decode(payload_chunk)
        signature = _decode(signature_chunk)
    except (binascii.Error, ValueError):
        return None

    if not payload or not signature:
        return None
    return SignedCode(
        issuer_id=issuer_id.strip(),
        algorithm=algorithm,
        payload=payload,
        signature=signature,
    )


@register
class SignedQrDetector(Detector):
    """Verifies an issuing authority's signature carried in a code on the card."""

    id = "rung0.signed_qr"
    rung = Rung.CRYPTOGRAPHIC

    def __init__(self, trust_store: TrustStore) -> None:
        """Hold the anchors this deployment was given.

        Args:
            trust_store: Issuer anchors, built by the caller. A detector never
                loads its own, so it cannot widen its own trust.
        """
        self._trust_store = trust_store

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Args:
            subject: The material under examination.

        Returns:
            Always true. A document carrying no code is reported as carrying no
            proof, rather than silently skipped, because "there was no signature
            to check" is exactly what an officer needs to be told.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Check any signed code on the document against this deployment's anchors.

        Args:
            subject: The material under examination.

        Returns:
            One piece of evidence. Never raises.
        """
        started = time.perf_counter()
        result, reasons = self._examine(subject)
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                reasons=reasons,
                standard_ref=STANDARD_REF,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )

    def _examine(self, subject: Subject) -> tuple[Result, tuple[str, ...]]:
        """Decide the result and the officer-facing reasons for one document."""
        if not subject.codes:
            return Result.NO_PROOF_PRESENT, (NO_CODE,)

        parsed = [
            container
            for container in (parse_container(code.payload) for code in subject.codes)
            if container is not None
        ]
        if not parsed:
            return Result.NO_PROOF_PRESENT, (NOT_OUR_CONTAINER,)

        when = subject.provenance.captured_at
        reports = [self._check(container, when=when) for container in parsed]

        for container, report in reports:
            if report.outcome is VerificationOutcome.VERIFIED:
                return Result.PROOF_VALID, (
                    f"The code on this document carries a signature from "
                    f"{container.issuer_id}, and it is genuine.",
                    "This is the strongest thing this system can establish about a "
                    "document: the authority that issued it signed exactly these details.",
                )

        for container, report in reports:
            if report.outcome is VerificationOutcome.NOT_VERIFIED:
                return Result.PROOF_INVALID, (
                    f"The code on this document claims to be signed by "
                    f"{container.issuer_id}, and that signature does not match. "
                    f"The details on it have been changed since it was issued, or it "
                    f"was never signed by them.",
                )

        return Result.NO_PROOF_PRESENT, (reports[0][1].reason,)

    def _check(
        self, container: SignedCode, *, when: datetime.datetime
    ) -> tuple[SignedCode, object]:
        """Verify one container against the anchor it names."""
        report = verify_detached(
            container.payload,
            container.signature,
            anchor=self._trust_store.anchor(container.issuer_id),
            algorithm=container.algorithm,
            when=when,
        )
        return container, report


def build(trust_store: TrustStore) -> Detector:
    """Construct the signed code detector.

    Args:
        trust_store: The anchors this deployment holds. An empty store means no
            document can be cleared here, which is correct for a deployment
            nobody has provisioned.

    Returns:
        The detector.
    """
    return SignedQrDetector(trust_store)
