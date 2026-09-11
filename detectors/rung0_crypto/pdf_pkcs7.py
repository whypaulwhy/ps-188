"""Rung 0 detector: verify PKCS#7 signatures embedded in a signed PDF.

A signed PDF carries a CMS signature over a byte range covering the whole file
except the signature hole itself. Verifying it establishes two separate things,
and conflating them is how a tampered document gets cleared:

* **intact** — the bytes still match what was signed;
* **trusted** — the signer chains to a certificate this deployment pinned.

The underlying library reports a third flag, `valid`, which says only that the
signature object is internally well formed. A tampered document still reports
`valid`. This detector therefore requires **intact and valid and trusted**
together before it will emit ``PROOF_VALID``.

**Revocation is not checked.** That needs a network connection, and there is
none at an open crossing. The check is therefore performed in a mode that does
not fail on missing revocation data, and every clearance says so in its own
reasons rather than leaving the officer to assume otherwise.
"""

from __future__ import annotations

import io
import time
from typing import Final

from core.contracts import DOCUMENT_ROLE, Artefact, Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung0_crypto.trust_store import TrustStore

DETECTOR_VERSION: Final[str] = "pdf_pkcs7/1.0.0"
STANDARD_REF: Final[str] = "ISO 32000-2 s.12.8.3.3 (PKCS#7 / CMS), RFC 5652"
PDF_MEDIA_TYPE: Final[str] = "application/pdf"

REVOCATION_NOTICE: Final[str] = (
    "Whether this document was withdrawn after it was issued could not be "
    "checked here, because that needs a network connection this checkpoint "
    "does not have."
)


@register
class PdfPkcs7SignatureDetector(Detector):
    """Verifies the CMS signature embedded in a signed PDF."""

    id = "rung0.pdf_pkcs7"
    rung = Rung.CRYPTOGRAPHIC

    def __init__(self, trust_store: TrustStore) -> None:
        """Hold the anchors this detector may verify against.

        Args:
            trust_store: Reviewed issuer anchors, supplied by the caller.
        """
        self._trust_store = trust_store

    @staticmethod
    def _document(subject: Subject) -> Artefact | None:
        """Return the document if it is a PDF.

        Only the document is ever examined. A signed PDF sent alongside it, as a
        photograph of the person for instance, is not the document, and verifying
        it would clear a case on a signature the document never carried.
        """
        document = subject.artefact(DOCUMENT_ROLE)
        if document is None or document.media_type != PDF_MEDIA_TYPE:
            return None
        return document

    def applies_to(self, subject: Subject) -> bool:
        """Report whether the document is a PDF.

        Args:
            subject: The material under examination.

        Returns:
            Whether the document itself is a PDF.
        """
        return self._document(subject) is not None

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Verify the embedded signature and report what was established.

        Args:
            subject: The material under examination.

        Returns:
            One piece of evidence, or none when the document is not a PDF.
            Never raises.
        """
        started = time.perf_counter()
        artefact = self._document(subject)
        if artefact is None:
            return ()

        result, reasons = self._examine(artefact.data)
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                reasons=reasons,
                standard_ref=STANDARD_REF,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=artefact.sha256,
            ),
        )

    def _examine(self, document: bytes) -> tuple[Result, tuple[str, ...]]:
        """Decide the result and the officer-facing reasons for one PDF."""
        if not len(self._trust_store):
            return Result.NO_PROOF_PRESENT, (
                "This checkpoint holds no issuing authority keys, so the "
                "signature on this document could not be checked.",
            )

        try:
            status = self._validate(document)
        except _NoSignatureError:
            return Result.NO_PROOF_PRESENT, (
                "This document carries no digital signature, so there was nothing to check.",
            )
        except Exception:  # failure is a result, not a crash
            return Result.NO_PROOF_PRESENT, (
                "The signature on this document could not be read, so nothing "
                "about it was confirmed.",
            )

        intact, valid, trusted, recognised = status

        if not recognised:
            return Result.NO_PROOF_PRESENT, (
                "This document is signed by an authority this checkpoint does "
                "not recognise, so nothing about it was confirmed.",
            )
        if intact and valid and trusted:
            return Result.PROOF_VALID, (
                "The issuing authority's digital signature on this document is genuine.",
                REVOCATION_NOTICE,
            )
        return Result.PROOF_INVALID, (
            "This document carries a signature from an authority this "
            "checkpoint recognises, and the document does not match what was "
            "signed. It has been altered since it was issued.",
        )

    def _validate(self, document: bytes) -> tuple[bool, bool, bool, bool]:
        """Return the intact, valid, trusted and recognised flags for the first signature.

        `recognised` is decided separately from validation, and has to be.
        The library reports a signature as untrusted whenever the document is
        not intact, so trust alone cannot distinguish a document altered after
        signing from one signed by an authority we never held a key for. Those
        two produce opposite outcomes — a rejection and a shrug — so they are
        told apart by looking at who signed it, independently of whether the
        bytes still match.

        The recognition test is certificate identity, or an issuer name
        matching one of our anchors. With a real multi-level certificate chain
        a leaf would satisfy neither, and the case would fall through to
        `NO_PROOF_PRESENT`. That is the safe direction, and it is a known
        limitation to revisit when a real issuer chain is available.
        """
        from asn1crypto import x509 as asn1x509  # kept out of import time
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext

        reader = PdfFileReader(io.BytesIO(document))
        signatures = reader.embedded_signatures
        if not signatures:
            raise _NoSignatureError

        context = ValidationContext(
            trust_roots=[
                asn1x509.Certificate.load(der) for der in self._trust_store.certificates()
            ],
            allow_fetching=False,
            revocation_mode="soft-fail",
        )
        signer = signatures[0].signer_cert
        pinned = self._trust_store.certificates()
        recognised = signer.dump() in pinned or any(
            signer.issuer == asn1x509.Certificate.load(der).subject for der in pinned
        )

        status = validate_pdf_signature(signatures[0], context)
        return bool(status.intact), bool(status.valid), bool(status.trusted), recognised


class _NoSignatureError(Exception):
    """Raised internally when a PDF carries no signature at all."""


def build(trust_store: TrustStore) -> Detector:
    """Construct the signed-PDF PKCS#7 detector.

    Args:
        trust_store: The anchors it may verify against.

    Returns:
        The detector.
    """
    return PdfPkcs7SignatureDetector(trust_store)
