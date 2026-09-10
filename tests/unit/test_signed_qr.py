"""The signed identity code: what it clears, what it rejects, what it refuses.

The three outcomes at the bottom of this file are the whole point of Rung 0
existing. Everything above them is about the parser refusing to treat something
as a signed code when it is not one — because a container that parses loosely is
a container an attacker can shape.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import pathlib
import tempfile
from typing import Final

import pytest

from api.trust import load_certificate
from core.contracts import Artefact, DecodedCode, DocumentType, Provenance, Result, Subject
from datagen.signed_card import ALGORITHM, CONTAINER_PREFIX, ISSUER_ID, generate_signed_card
from detectors.rung0_crypto.signed_qr import build, parse_container
from detectors.rung0_crypto.trust_store import SignatureAlgorithm, TrustAnchor, TrustStore
from extraction.preprocess import decode, normalise
from extraction.qr_decode import decode_qr, decoder_available

NOW: Final[datetime.datetime] = datetime.datetime(2026, 9, 10, 12, 0, tzinfo=datetime.UTC)


def b64(raw: bytes) -> str:
    """Base64url without padding, as the container carries it."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def container(
    *,
    prefix: str = CONTAINER_PREFIX,
    issuer: str = ISSUER_ID,
    algorithm: str = ALGORITHM,
    payload: str = "cGF5bG9hZA",
    signature: str = "c2ln",
) -> bytes:
    """Assemble a container, overriding one field at a time."""
    return "|".join([prefix, issuer, algorithm, payload, signature]).encode("ascii")


# What the parser accepts


def test_a_well_formed_container_parses() -> None:
    """The ordinary path, or none of the refusals below mean anything."""
    parsed = parse_container(container(payload=b64(b"hello"), signature=b64(b"sig")))

    assert parsed is not None
    assert parsed.issuer_id == ISSUER_ID
    assert parsed.payload == b"hello"
    assert parsed.signature == b"sig"


def test_padding_may_be_omitted() -> None:
    """A writer that strips base64 padding must still be readable."""
    payload = b"twelve bytes"
    assert parse_container(container(payload=b64(payload))) is not None


# What the parser refuses


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("not a container", b"https://example.gov/verify/12345"),
        ("wrong prefix", container(prefix="SENTINELID-SQR9")),
        ("too few fields", b"SENTINELID-SQR1|issuer|ECDSA_SHA256|payload"),
        ("too many fields", container() + b"|extra"),
        ("empty issuer", container(issuer="   ")),
        ("unknown algorithm", container(algorithm="RSA_PKCS1V15_SHA1")),
        ("payload not base64", container(payload="not base64!!")),
        ("empty payload", container(payload="")),
        ("empty signature", container(signature="")),
        ("not ascii", "SENTINELID-SQR1|issuer|ECDSA_SHA256|x|yé".encode()),
    ],
)
def test_the_parser_refuses(label: str, raw: bytes) -> None:
    """None is not a finding of forgery: most codes are simply not this format."""
    assert parse_container(raw) is None, label


# The card generator


def test_the_generated_card_carries_a_readable_code() -> None:
    """A code that cannot be read makes every check below vacuous."""
    if not decoder_available():
        pytest.skip("no code reader on this machine")

    card = generate_signed_card()
    payloads, _ = decode_qr(normalise(decode(card.png)))

    assert payloads, "the rendered card carried no readable code"
    assert payloads[0] == card.container, "the code did not round trip exactly"


def test_the_generator_does_not_write_the_signing_key() -> None:
    """The one thing that can mint documents which clear is handed back, not left."""
    card = generate_signed_card()

    assert card.private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")


# The three outcomes


def anchored(card: object, *, algorithm: SignatureAlgorithm) -> TrustStore:
    """Install the card's issuer the way an operator would."""
    path = pathlib.Path(tempfile.mkdtemp()) / "issuer.der"
    path.write_bytes(card.certificate_der)  # type: ignore[attr-defined]
    certificate = load_certificate(path)
    return TrustStore(
        [
            TrustAnchor(
                issuer_id=ISSUER_ID,
                public_key=certificate.public_key(),
                permitted_algorithms=frozenset({algorithm}),
                not_before=certificate.not_valid_before_utc,
                not_after=certificate.not_valid_after_utc,
                certificate_der=card.certificate_der,  # type: ignore[attr-defined]
            )
        ]
    )


def subject_for(card: object) -> Subject:
    """Build a subject carrying the card's code, as extraction would."""
    png: bytes = card.png  # type: ignore[attr-defined]
    digest = hashlib.sha256(png).hexdigest()
    return Subject(
        provenance=Provenance(
            source_id="case-signed",
            sha256=digest,
            media_type="image/png",
            byte_size=len(png),
            captured_at=NOW,
            received_at=NOW,
            checkpoint_id="ssb-demo-01",
        ),
        declared_type=DocumentType.UNRECOGNISED,
        artefacts=(
            Artefact(role="document_front", media_type="image/png", sha256=digest, data=png),
        ),
        codes=(DecodedCode(symbology="QR", payload=card.container),),  # type: ignore[attr-defined]
    )


def test_a_genuine_card_proves_itself() -> None:
    """The only thing in this system that can clear a document."""
    card = generate_signed_card(signed_at=NOW - datetime.timedelta(days=30))
    store = anchored(card, algorithm=SignatureAlgorithm.ECDSA_SHA256)

    evidence = build(store).run(subject_for(card))[0]

    assert evidence.result is Result.PROOF_VALID


def test_a_card_edited_after_signing_is_rejected() -> None:
    """The case the whole rung exists to catch."""
    card = generate_signed_card(
        signed_at=NOW - datetime.timedelta(days=30), tamper_after_signing=True
    )
    store = anchored(card, algorithm=SignatureAlgorithm.ECDSA_SHA256)

    evidence = build(store).run(subject_for(card))[0]

    assert evidence.result is Result.PROOF_INVALID


def test_a_genuine_card_proves_nothing_without_the_issuer_key() -> None:
    """Not holding a key is not a finding of forgery, and must not read as one."""
    card = generate_signed_card(signed_at=NOW - datetime.timedelta(days=30))

    evidence = build(TrustStore()).run(subject_for(card))[0]

    assert evidence.result is Result.NO_PROOF_PRESENT


def test_an_anchor_that_forbids_the_algorithm_does_not_clear() -> None:
    """The allowlist is what stops a forger choosing a weaker construction."""
    card = generate_signed_card(signed_at=NOW - datetime.timedelta(days=30))
    store = anchored(card, algorithm=SignatureAlgorithm.RSA_PKCS1V15_SHA256)

    evidence = build(store).run(subject_for(card))[0]

    assert evidence.result is Result.NO_PROOF_PRESENT


def test_a_document_with_no_code_carries_no_proof() -> None:
    """Most documents at these borders have nothing to check, and say so."""
    card = generate_signed_card()
    subject = subject_for(card).model_copy(update={"codes": ()})

    evidence = build(TrustStore()).run(subject)[0]

    assert evidence.result is Result.NO_PROOF_PRESENT
    assert "no code" in evidence.reasons[0].lower()
