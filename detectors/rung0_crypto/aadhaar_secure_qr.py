"""Rung 0 detector: verify the UIDAI Secure QR signature on an Aadhaar document.

**Deliberately unimplemented.** The cryptography is ordinary RSA with SHA-256
and is already available in :mod:`detectors.rung0_crypto.verification`. What is
missing is the container: the exact byte layout that separates the signed data
from the signature.

Writing that parser from an incomplete reading of the specification would put a
guess behind the only rung that can clear a document. A subtly wrong field
boundary produces a detector that verifies the wrong bytes, and the failure mode
is silent: it would report ``PROOF_VALID`` on documents it had not actually
checked. `docs/scope.md` already lists the exact current formats as unconfirmed.

**What is needed to finish this**, so the gap is actionable rather than vague:

1. A specimen Aadhaar Secure QR payload, ideally several, from a document whose
   authenticity is known. Synthetic payloads generated from our own reading of
   the format would prove only that the code agrees with itself.
2. The UIDAI public certificate currently in use, and how a deployment is meant
   to obtain and pin it.
3. Confirmation of the container layout: the big-integer to byte-string
   decoding, whether the payload is compressed and with what, the field
   delimiter, the length and position of the signature, and where the embedded
   photograph begins and ends.
4. Confirmation of which byte range the signature actually covers, which is the
   single detail most likely to be got wrong.

Until then, a deployment holding no Aadhaar anchor reports
``NO_PROOF_PRESENT`` for these documents, which is the honest answer: nothing
about the document was confirmed. See ``docs/roadmap.md``.
"""

from __future__ import annotations

from detectors.base import Detector
from detectors.rung0_crypto.trust_store import TrustStore


def build(trust_store: TrustStore) -> Detector:
    """Construct the Aadhaar Secure QR signature detector.

    Args:
        trust_store: The anchors it would verify against.

    Returns:
        The detector.

    Raises:
        NotImplementedError: Always. See the module docstring for exactly what
            is needed to complete this.
    """
    raise NotImplementedError(
        "detectors.rung0_crypto.aadhaar_secure_qr needs a real Secure QR specimen "
        "and the UIDAI certificate before it can be written; see the module docstring"
    )
