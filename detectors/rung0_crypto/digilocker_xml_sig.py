"""Rung 0 detector: verify the XML signature on a DigiLocker issued document.

DigiLocker issues documents as XML carrying an enveloped XMLDSig signature.
The document schema varies by issuer; the signature envelope is a public
standard, which is why this detector can be written and tested now while the
Aadhaar Secure QR container cannot.

**The embedded certificate is never trusted on its own.** An XMLDSig signature
carries the signer's certificate inside it, and a forger controls that
completely. Verification is always against a certificate pinned in the
:class:`~detectors.rung0_crypto.trust_store.TrustStore` this detector was
handed. The embedded certificate is used for one thing only: deciding whether
we are looking at a document from an issuer we know, so that a failure can be
reported as tampering rather than as an unknown issuer.

That distinction decides whether a traveller is turned back:

* signature verifies against a pinned anchor -> ``PROOF_VALID``;
* the signer is an issuer we hold an anchor for, and verification fails ->
  ``PROOF_INVALID``, which rejects;
* anything else, including a valid-looking signature from an issuer we do not
  know -> ``NO_PROOF_PRESENT``, which establishes nothing.
"""

from __future__ import annotations

import time
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from core.contracts import Evidence, Result, Rung, Subject
from detectors.base import Detector, register
from detectors.rung0_crypto.trust_store import TrustStore

DETECTOR_VERSION: Final[str] = "digilocker_xml_sig/1.0.0"
STANDARD_REF: Final[str] = "W3C XML Signature Syntax and Processing 1.1, s.3.2"
XML_MEDIA_TYPES: Final[frozenset[str]] = frozenset({"application/xml", "text/xml"})


def _embedded_certificate(document: bytes) -> bytes | None:
    """Return the DER of the certificate embedded in the signature, if there is one.

    Args:
        document: The signed XML.

    Returns:
        The DER encoding, or None if the document carries no readable
        certificate. Never used to decide trust; only to decide whether the
        signer is an issuer we know.
    """
    try:
        from lxml import etree  # kept out of import time on purpose

        root = etree.fromstring(document)  # parsed only to read a certificate
        nodes = root.findall(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        if not nodes or not nodes[0].text:
            return None
        pem = f"-----BEGIN CERTIFICATE-----\n{nodes[0].text.strip()}\n-----END CERTIFICATE-----\n"
        return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    except Exception:  # a detector never crashes; an unreadable document is a result
        return None


@register
class DigiLockerXmlSignatureDetector(Detector):
    """Verifies the XMLDSig signature on a DigiLocker issued document."""

    id = "rung0.digilocker_xml_sig"
    rung = Rung.CRYPTOGRAPHIC

    def __init__(self, trust_store: TrustStore) -> None:
        """Hold the anchors this detector may verify against.

        Args:
            trust_store: Reviewed issuer anchors, supplied by the caller. An
                empty store means nothing can be cleared, which every case will
                then say out loud.
        """
        self._trust_store = trust_store

    def applies_to(self, subject: Subject) -> bool:
        """Report whether the subject carries an XML artefact to check.

        Args:
            subject: The material under examination.

        Returns:
            Whether any artefact is XML.
        """
        return any(artefact.media_type in XML_MEDIA_TYPES for artefact in subject.artefacts)

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Verify the signature and report what was established.

        Args:
            subject: The material under examination.

        Returns:
            One piece of evidence. Never raises.
        """
        started = time.perf_counter()
        artefact = next(
            (item for item in subject.artefacts if item.media_type in XML_MEDIA_TYPES), None
        )
        if artefact is None:  # pragma: no cover - guarded by applies_to
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
        """Decide the result and the officer-facing reasons for one document."""
        if not len(self._trust_store):
            return Result.NO_PROOF_PRESENT, (
                "This checkpoint holds no issuing authority keys, so the "
                "signature on this document could not be checked.",
            )

        for certificate in self._trust_store.certificates():
            if self._verifies_against(document, certificate):
                return Result.PROOF_VALID, (
                    "The issuing authority's digital signature on this document is genuine.",
                )

        embedded = _embedded_certificate(document)
        if embedded is not None and embedded in self._trust_store.certificates():
            return Result.PROOF_INVALID, (
                "This document carries a signature from an authority this "
                "checkpoint recognises, and that signature does not match the "
                "contents of the document. It has been altered since it was "
                "issued, or it was never issued.",
            )

        return Result.NO_PROOF_PRESENT, (
            "This document is signed by an authority this checkpoint does not "
            "recognise, so nothing about it was confirmed.",
        )

    @staticmethod
    def _verifies_against(document: bytes, certificate_der: bytes) -> bool:
        """Report whether the document's signature verifies against one pinned certificate."""
        try:
            from signxml import XMLVerifier  # kept out of import time

            pem = x509.load_der_x509_certificate(certificate_der).public_bytes(
                serialization.Encoding.PEM
            )
            XMLVerifier().verify(document, x509_cert=pem.decode())
        except Exception:  # failure is a result, not a crash
            return False
        return True


def build(trust_store: TrustStore) -> Detector:
    """Construct the DigiLocker XML signature detector.

    Args:
        trust_store: The anchors it may verify against.

    Returns:
        The detector.
    """
    return DigiLockerXmlSignatureDetector(trust_store)
