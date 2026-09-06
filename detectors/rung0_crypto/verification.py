"""The format-agnostic core of Rung 0: does this signature verify against this key?

Every Rung 0 detector reduces to this question eventually. The container
differs — a QR payload, an XML envelope, a PDF byte range — but once the
payload bytes and the signature bytes have been extracted, the check is the
same, and it is worth having in one place that can be read in a sitting.

**The three-way outcome is the whole point.** A signature that fails to verify
is not the same as a signature that could not be checked:

* `VERIFIED` — the signature is genuine. This is the only outcome that can
  clear a document, and it is reachable by exactly one path below.
* `NOT_VERIFIED` — the signature was checked and is wrong. The document is not
  what it claims to be. This rejects, so it is claimed only when certain.
* `CANNOT_VERIFY` — no anchor, expired anchor, disallowed algorithm, wrong key
  type, malformed input, or anything unexpected. Establishes nothing. Clears
  nothing, rejects nothing.

Every failure that is not a cryptographic mismatch lands in `CANNOT_VERIFY`,
including exceptions this module did not anticipate. A Rung 0 detector that
crashes is indistinguishable from one that found nothing wrong, and CLAUDE.md
calls that a defect rather than a clean result.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from detectors.rung0_crypto.trust_store import (
    MINIMUM_RSA_KEY_BITS,
    SignatureAlgorithm,
    TrustAnchor,
)


class VerificationOutcome(StrEnum):
    """What a signature check established."""

    VERIFIED = "VERIFIED"
    """The signature is genuine. The only outcome that can clear a document."""

    NOT_VERIFIED = "NOT_VERIFIED"
    """The signature was checked and does not match. The document is not genuine."""

    CANNOT_VERIFY = "CANNOT_VERIFY"
    """The check could not be made. Establishes nothing either way."""


@dataclass(frozen=True)
class VerificationReport:
    """The result of one signature check, with a reason an officer can read."""

    outcome: VerificationOutcome
    """What was established."""

    reason: str
    """Plain language, no jargon. Goes straight into `Evidence.reasons`."""

    issuer_id: str | None = None
    """Which anchor was used, when one was."""

    algorithm: SignatureAlgorithm | None = None
    """Which algorithm was attempted, when one was selected."""


def _key_matches_algorithm(anchor: TrustAnchor, algorithm: SignatureAlgorithm) -> bool:
    """Report whether an anchor's key type can perform an algorithm."""
    key = anchor.public_key
    if algorithm is SignatureAlgorithm.ED25519:
        return isinstance(key, Ed25519PublicKey)
    if algorithm in (SignatureAlgorithm.RSA_PKCS1V15_SHA256, SignatureAlgorithm.RSA_PSS_SHA256):
        return isinstance(key, rsa.RSAPublicKey) and key.key_size >= MINIMUM_RSA_KEY_BITS
    return isinstance(key, ec.EllipticCurvePublicKey)


def _perform(
    anchor: TrustAnchor, algorithm: SignatureAlgorithm, payload: bytes, signature: bytes
) -> None:
    """Run the underlying verification, raising `InvalidSignature` on mismatch.

    The key type has already been matched to the algorithm by
    :func:`_key_matches_algorithm`, and any residual mismatch raises, which the
    caller turns into `CANNOT_VERIFY`.
    """
    key = anchor.public_key
    if algorithm is SignatureAlgorithm.ED25519:
        cast(Ed25519PublicKey, key).verify(signature, payload)
    elif algorithm is SignatureAlgorithm.RSA_PKCS1V15_SHA256:
        cast(rsa.RSAPublicKey, key).verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm is SignatureAlgorithm.RSA_PSS_SHA256:
        cast(rsa.RSAPublicKey, key).verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    else:
        cast(ec.EllipticCurvePublicKey, key).verify(signature, payload, ec.ECDSA(hashes.SHA256()))


def verify_detached(
    payload: bytes,
    signature: bytes,
    *,
    anchor: TrustAnchor | None,
    algorithm: SignatureAlgorithm,
    when: datetime.datetime,
) -> VerificationReport:
    """Check a detached signature over a payload against a trust anchor.

    Args:
        payload: The exact bytes that were signed.
        signature: The signature bytes.
        anchor: The issuer anchor to check against, or None if this deployment
            holds no anchor for the claimed issuer.
        algorithm: The algorithm the signature claims to use.
        when: The instant to judge anchor validity against, passed in so a case
            replays to the same answer years later.

    Returns:
        A report. `VERIFIED` is reachable only by a successful cryptographic
        check against a currently valid anchor that permits the algorithm.
    """
    if anchor is None:
        return VerificationReport(
            VerificationOutcome.CANNOT_VERIFY,
            "This deployment does not hold the issuing authority's key, so the "
            "signature on this document could not be checked.",
            algorithm=algorithm,
        )

    if not anchor.is_valid_at(when):
        return VerificationReport(
            VerificationOutcome.CANNOT_VERIFY,
            "The issuing authority's key held by this checkpoint is out of date, "
            "so the signature could not be checked.",
            issuer_id=anchor.issuer_id,
            algorithm=algorithm,
        )

    if not anchor.permits(algorithm) or not _key_matches_algorithm(anchor, algorithm):
        return VerificationReport(
            VerificationOutcome.CANNOT_VERIFY,
            "This document is signed in a way this checkpoint is not set up to "
            "check, so nothing was confirmed about it.",
            issuer_id=anchor.issuer_id,
            algorithm=algorithm,
        )

    if not payload or not signature:
        return VerificationReport(
            VerificationOutcome.CANNOT_VERIFY,
            "The signed part of this document was empty, so there was nothing to check.",
            issuer_id=anchor.issuer_id,
            algorithm=algorithm,
        )

    try:
        _perform(anchor, algorithm, payload, signature)
    except InvalidSignature:
        return VerificationReport(
            VerificationOutcome.NOT_VERIFIED,
            "The issuing authority's signature does not match the contents of "
            "this document. The document has been altered since it was issued, "
            "or it was never issued.",
            issuer_id=anchor.issuer_id,
            algorithm=algorithm,
        )
    except Exception:  # a detector must never crash; see the module docstring
        return VerificationReport(
            VerificationOutcome.CANNOT_VERIFY,
            "The signature on this document could not be read, so nothing was confirmed about it.",
            issuer_id=anchor.issuer_id,
            algorithm=algorithm,
        )

    return VerificationReport(
        VerificationOutcome.VERIFIED,
        "The issuing authority's digital signature on this document is genuine.",
        issuer_id=anchor.issuer_id,
        algorithm=algorithm,
    )
