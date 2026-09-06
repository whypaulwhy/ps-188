"""The Rung 0 verification core and the trust store.

Rung 0 is the only rung that can clear a document, so these tests are mostly
about the paths that must **not** reach `VERIFIED`. There are many more ways to
fail to check a signature than to check one, and each of them has to land in
`CANNOT_VERIFY` rather than in either of the two outcomes that decide a case.

The committed seed below derives the same Ed25519 key on every machine and
every run, so the fixtures are reproducible without any key material existing
in the repository. RSA and ECDSA keys are generated in-process, because those
paths matter — real issuers sign with RSA — and generating them is cheaper than
storing them.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from detectors.rung0_crypto.trust_store import (
    SignatureAlgorithm,
    TrustAnchor,
    TrustStore,
)
from detectors.rung0_crypto.verification import (
    VerificationOutcome,
    verify_detached,
)

SEED = bytes(range(32))
"""A committed seed. Ed25519 keys derive from it deterministically, so nothing is stored."""

PAYLOAD = b"a document that was signed"
NOW = datetime.datetime(2026, 9, 6, 12, 0, tzinfo=datetime.UTC)
FROM = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
UNTIL = datetime.datetime(2036, 1, 1, tzinfo=datetime.UTC)


def ed25519_key() -> Ed25519PrivateKey:
    """Return the deterministic test issuer key."""
    return Ed25519PrivateKey.from_private_bytes(SEED)


def anchor(**overrides: object) -> TrustAnchor:
    """Build a trust anchor for the Ed25519 test issuer."""
    fields: dict[str, object] = {
        "issuer_id": "test-issuer",
        "public_key": ed25519_key().public_key(),
        "permitted_algorithms": frozenset({SignatureAlgorithm.ED25519}),
        "not_before": FROM,
        "not_after": UNTIL,
    }
    fields.update(overrides)
    return TrustAnchor(**fields)  # type: ignore[arg-type]


def check(**overrides: object) -> VerificationOutcome:
    """Verify a good Ed25519 signature, with any argument replaced."""
    fields: dict[str, object] = {
        "payload": PAYLOAD,
        "signature": ed25519_key().sign(PAYLOAD),
        "anchor": anchor(),
        "algorithm": SignatureAlgorithm.ED25519,
        "when": NOW,
    }
    fields.update(overrides)
    payload = fields.pop("payload")
    signature = fields.pop("signature")
    return verify_detached(payload, signature, **fields).outcome  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The seed
# ---------------------------------------------------------------------------


def test_the_seed_derives_the_same_key_every_time() -> None:
    """Fixtures are reproducible without a private key existing anywhere."""
    assert ed25519_key().private_bytes_raw() == ed25519_key().private_bytes_raw()
    assert ed25519_key().sign(PAYLOAD) == ed25519_key().sign(PAYLOAD)


# ---------------------------------------------------------------------------
# The one path to VERIFIED
# ---------------------------------------------------------------------------


def test_a_genuine_signature_verifies() -> None:
    """The only outcome that can clear a document."""
    assert check() is VerificationOutcome.VERIFIED


def test_the_report_names_the_issuer_and_algorithm() -> None:
    """A clearance has to be traceable to which key established it."""
    report = verify_detached(
        PAYLOAD,
        ed25519_key().sign(PAYLOAD),
        anchor=anchor(),
        algorithm=SignatureAlgorithm.ED25519,
        when=NOW,
    )

    assert report.issuer_id == "test-issuer"
    assert report.algorithm is SignatureAlgorithm.ED25519
    assert "genuine" in report.reason


# ---------------------------------------------------------------------------
# The one path to NOT_VERIFIED
# ---------------------------------------------------------------------------


def test_an_altered_payload_does_not_verify() -> None:
    """The signature was checked and is wrong. This is what rejects a document."""
    assert check(payload=b"a document that was altered") is VerificationOutcome.NOT_VERIFIED


def test_a_signature_from_another_key_does_not_verify() -> None:
    """A forger's own signature is a mismatch, not an unreadable document."""
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))

    assert check(signature=other.sign(PAYLOAD)) is VerificationOutcome.NOT_VERIFIED


def test_the_rejection_reason_is_readable_by_an_officer() -> None:
    """A rejection turns someone back, so the sentence has to explain itself."""
    report = verify_detached(
        b"altered",
        ed25519_key().sign(PAYLOAD),
        anchor=anchor(),
        algorithm=SignatureAlgorithm.ED25519,
        when=NOW,
    )

    assert "altered since it was issued" in report.reason


# ---------------------------------------------------------------------------
# Everything else must be CANNOT_VERIFY
# ---------------------------------------------------------------------------


def test_no_anchor_cannot_verify() -> None:
    """A deployment that never received the issuer's key establishes nothing."""
    assert check(anchor=None) is VerificationOutcome.CANNOT_VERIFY


@pytest.mark.parametrize(
    "when",
    [
        datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        datetime.datetime(2037, 1, 1, tzinfo=datetime.UTC),
    ],
)
def test_an_anchor_outside_its_window_cannot_verify(when: datetime.datetime) -> None:
    """An expired or not-yet-valid issuer key does not clear a document."""
    assert check(when=when) is VerificationOutcome.CANNOT_VERIFY


def test_an_algorithm_the_anchor_does_not_permit_cannot_verify() -> None:
    """The allowlist is per anchor, so one issuer's key cannot be used another way."""
    restricted = anchor(permitted_algorithms=frozenset({SignatureAlgorithm.RSA_PSS_SHA256}))

    assert check(anchor=restricted) is VerificationOutcome.CANNOT_VERIFY


def test_a_key_of_the_wrong_type_cannot_verify() -> None:
    """An anchor holding an RSA key cannot perform an Ed25519 check."""
    wrong = anchor(
        public_key=rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
        permitted_algorithms=frozenset({SignatureAlgorithm.ED25519}),
    )

    assert check(anchor=wrong) is VerificationOutcome.CANNOT_VERIFY


def test_an_rsa_key_below_the_minimum_size_cannot_verify() -> None:
    """A short RSA key is refused whatever the anchor claims to permit."""
    # A deliberately weak key: the point of the test is that it is refused.
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    weak_anchor = anchor(
        public_key=weak.public_key(),
        permitted_algorithms=frozenset({SignatureAlgorithm.RSA_PKCS1V15_SHA256}),
    )
    signature = weak.sign(PAYLOAD, padding.PKCS1v15(), hashes.SHA256())

    assert (
        check(
            anchor=weak_anchor,
            algorithm=SignatureAlgorithm.RSA_PKCS1V15_SHA256,
            signature=signature,
        )
        is VerificationOutcome.CANNOT_VERIFY
    )


@pytest.mark.parametrize(("payload", "signature"), [(b"", b"x"), (PAYLOAD, b"")])
def test_empty_input_cannot_verify(payload: bytes, signature: bytes) -> None:
    """There is nothing to check, which is not the same as finding something wrong."""
    assert check(payload=payload, signature=signature) is VerificationOutcome.CANNOT_VERIFY


def test_a_malformed_signature_never_crashes() -> None:
    """A detector that raises is indistinguishable from one that found nothing wrong."""
    outcome = check(signature=b"not a signature at all")

    assert outcome in (VerificationOutcome.NOT_VERIFIED, VerificationOutcome.CANNOT_VERIFY)
    assert outcome is not VerificationOutcome.VERIFIED


# ---------------------------------------------------------------------------
# The algorithms real issuers use
# ---------------------------------------------------------------------------


def test_rsa_pkcs1v15_verifies() -> None:
    """The construction Aadhaar and DigiLocker actually sign with."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = key.sign(PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
    rsa_anchor = anchor(
        public_key=key.public_key(),
        permitted_algorithms=frozenset({SignatureAlgorithm.RSA_PKCS1V15_SHA256}),
    )

    assert (
        check(
            anchor=rsa_anchor,
            algorithm=SignatureAlgorithm.RSA_PKCS1V15_SHA256,
            signature=signature,
        )
        is VerificationOutcome.VERIFIED
    )


def test_rsa_pss_verifies() -> None:
    """The modern padding, permitted separately from the legacy one."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = key.sign(
        PAYLOAD,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    rsa_anchor = anchor(
        public_key=key.public_key(),
        permitted_algorithms=frozenset({SignatureAlgorithm.RSA_PSS_SHA256}),
    )

    assert (
        check(anchor=rsa_anchor, algorithm=SignatureAlgorithm.RSA_PSS_SHA256, signature=signature)
        is VerificationOutcome.VERIFIED
    )


def test_ecdsa_verifies() -> None:
    """Some issuer chains use elliptic curve keys."""
    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(PAYLOAD, ec.ECDSA(hashes.SHA256()))
    ec_anchor = anchor(
        public_key=key.public_key(),
        permitted_algorithms=frozenset({SignatureAlgorithm.ECDSA_SHA256}),
    )

    assert (
        check(anchor=ec_anchor, algorithm=SignatureAlgorithm.ECDSA_SHA256, signature=signature)
        is VerificationOutcome.VERIFIED
    )


def test_there_is_no_sha1_algorithm_to_select() -> None:
    """Weak constructions are absent from the vocabulary rather than discouraged."""
    names = {member.value for member in SignatureAlgorithm}

    assert not any("SHA1" in name or "MD5" in name for name in names)


# ---------------------------------------------------------------------------
# Trust anchors and the store
# ---------------------------------------------------------------------------


def test_an_anchor_must_name_its_issuer() -> None:
    """A decision has to be traceable to which key established it."""
    with pytest.raises(ValueError, match="must name its issuer"):
        anchor(issuer_id="   ")


@pytest.mark.parametrize("field", ["not_before", "not_after"])
def test_anchor_timestamps_must_carry_a_timezone(field: str) -> None:
    """A naive timestamp cannot be placed on a timeline."""
    with pytest.raises(ValueError, match="timezone aware"):
        anchor(**{field: datetime.datetime(2026, 1, 1)})


def test_an_anchor_window_cannot_be_inverted() -> None:
    """An anchor valid for no time at all is a configuration error."""
    with pytest.raises(ValueError, match="non-empty"):
        anchor(not_before=UNTIL, not_after=FROM)


def test_two_anchors_cannot_claim_the_same_issuer() -> None:
    """A duplicate would make anchor selection arbitrary."""
    with pytest.raises(ValueError, match="same issuer_id"):
        TrustStore([anchor(), anchor()])


def test_an_empty_store_is_legitimate_and_clears_nothing() -> None:
    """A deployment not yet provisioned with issuer keys is a real state."""
    store = TrustStore()

    assert len(store) == 0
    assert store.anchor("test-issuer") is None
    assert store.certificates() == ()


def test_anchors_are_found_by_issuer() -> None:
    """The ordinary lookup."""
    store = TrustStore([anchor(), anchor(issuer_id="other")])

    assert store.anchor("other") is not None
    assert store.anchor("absent") is None
    assert len(store) == 2
    assert [item.issuer_id for item in store] == ["test-issuer", "other"]


def test_only_anchors_carrying_a_certificate_are_offered_as_certificates() -> None:
    """Formats that validate a chain need a certificate, not a bare key."""
    store = TrustStore([anchor(), anchor(issuer_id="with-cert", certificate_der=b"der")])

    assert store.certificates() == (b"der",)


def test_an_anchor_reports_its_own_window_and_allowlist() -> None:
    """Both limits belong to the anchor rather than to the caller."""
    item = anchor()

    assert item.is_valid_at(NOW)
    assert not item.is_valid_at(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
    assert item.permits(SignatureAlgorithm.ED25519)
    assert not item.permits(SignatureAlgorithm.ECDSA_SHA256)
