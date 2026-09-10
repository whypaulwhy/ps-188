"""Factories for building valid contract objects in tests.

Every helper here produces a *valid* object by default, so a test that wants to
exercise a rejection can override exactly one field and the reader can see
immediately what is being tested.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import subprocess
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from api.trust import load_certificate
from core.contracts import (
    Artefact,
    DocumentType,
    Evidence,
    Provenance,
    Result,
    Rung,
    Subject,
    TextZone,
    ZoneName,
)
from detectors.rung0_crypto.trust_store import (
    SignatureAlgorithm,
    TrustAnchor,
    TrustStore,
)

DIGEST: Final[str] = "a" * 64
"""A well-formed lowercase hex SHA-256 digest, used wherever the value is irrelevant."""

DECIDED_AT: Final[datetime.datetime] = datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.UTC)
"""A fixed decision timestamp, so verdicts in tests are byte-for-byte reproducible."""

STANDARD_REF: Final[dict[Rung, str]] = {
    Rung.CRYPTOGRAPHIC: "UIDAI Aadhaar Secure QR code specification s.3",
    Rung.DETERMINISTIC: "ICAO Doc 9303 Part 3 s.4.2.2",
}
"""A plausible citation for each rung that is required to carry one."""


def evidence(rung: Rung, result: Result, **overrides: Any) -> Evidence:  # noqa: ANN401
    """Build a valid piece of evidence at a given rung and result.

    Fields that the contract requires for that particular rung are filled in
    automatically: a standard reference at Rung 0 and Rung 1, and a score and
    uncertainty for conclusive Rung 2 results.

    Args:
        rung: The trust rung to declare.
        result: The outcome to report. Must be permitted at that rung unless the
            test is deliberately building an invalid object.
        **overrides: Any field to replace on the constructed evidence.

    Returns:
        The constructed evidence.
    """
    fields: dict[str, Any] = {
        "detector_id": f"rung{int(rung)}.{result.value.lower()}",
        "rung": rung,
        "result": result,
        "reasons": (f"A plain sentence describing {result.value}.",),
        "runtime_ms": 1.0,
        "model_version": "test/1",
        "input_digest": DIGEST,
    }
    if rung in STANDARD_REF:
        fields["standard_ref"] = STANDARD_REF[rung]
    if rung is Rung.INFERENCE and result is not Result.INCONCLUSIVE:
        fields["score"] = 0.5
        fields["uncertainty"] = 0.1
    fields.update(overrides)
    return Evidence(**fields)


def provenance(**overrides: Any) -> Provenance:  # noqa: ANN401
    """Build a valid provenance record.

    Args:
        **overrides: Any field to replace on the constructed record.

    Returns:
        The constructed provenance.
    """
    fields: dict[str, Any] = {
        "source_id": "capture-0001",
        "sha256": DIGEST,
        "media_type": "image/jpeg",
        "byte_size": 2048,
        "captured_at": DECIDED_AT,
        "received_at": DECIDED_AT,
        "checkpoint_id": "ssb-demo-01",
    }
    fields.update(overrides)
    return Provenance(**fields)


def subject(**overrides: Any) -> Subject:  # noqa: ANN401
    """Build a valid subject carrying a readable passport strip.

    Args:
        **overrides: Any field to replace on the constructed subject.

    Returns:
        The constructed subject.
    """
    data = b"a passport strip"
    fields: dict[str, Any] = {
        "provenance": provenance(),
        "declared_type": DocumentType.INDIAN_PASSPORT,
        "artefacts": (
            Artefact(role="document_front", media_type="text/plain", sha256=DIGEST, data=data),
        ),
        "zones": (
            TextZone(
                name=ZoneName.MRZ,
                lines=("P<INDSPECIMEN<<TEST<CASE<<<<<<<<<<<<<<<<<<<<",),
                complete=True,
            ),
        ),
    }
    fields.update(overrides)
    return Subject(**fields)


REPO_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).parents[1]
"""The repository root, one level above this package."""


def self_signed_certificate(
    folder: pathlib.Path,
    *,
    name: str = "issuer.pem",
    common_name: str = "Utopia Issuing Authority",
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    encoding: Encoding = Encoding.PEM,
) -> pathlib.Path:
    """Write one self-signed certificate for an imaginary issuer.

    Generated rather than committed: a committed certificate means a key pair in
    the repository, and the private half has to exist for the fixture to be
    built at all.

    Args:
        folder: Where to write it.
        name: The file name, which also decides the extension a reader sees.
        common_name: The subject, which no test asserts on but a person reading
            a failure will.
        not_before: Start of validity. Defaults to a year ago.
        not_after: End of validity. Defaults to a year ahead.
        encoding: PEM or DER, both of which the reader must accept.

    Returns:
        The path written.
    """
    start = not_before or (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=365))
    end = not_after or (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start.replace(tzinfo=None))
        .not_valid_after(end.replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )
    path = folder / name
    path.write_bytes(certificate.public_bytes(encoding))
    return path


def one_anchor_store(folder: pathlib.Path, *, issuer_id: str = "utopia") -> TrustStore:
    """Return a trust store holding exactly one anchor, for an equipped deployment.

    Args:
        folder: Somewhere to put the generated certificate.
        issuer_id: What to call the issuer.

    Returns:
        The store. A deployment holding this can reach `CLEARED`; one holding an
        empty store cannot, and says so on every case.
    """
    certificate = load_certificate(self_signed_certificate(folder))
    return TrustStore(
        [
            TrustAnchor(
                issuer_id=issuer_id,
                public_key=certificate.public_key(),
                permitted_algorithms=frozenset({SignatureAlgorithm.RSA_PKCS1V15_SHA256}),
                not_before=certificate.not_valid_before_utc,
                not_after=certificate.not_valid_after_utc,
                certificate_der=certificate.public_bytes(Encoding.DER),
            )
        ]
    )


def write_anchors_file(folder: pathlib.Path) -> pathlib.Path:
    """Write a complete anchors file plus the certificate it names.

    Returns:
        The anchors file, ready for `SENTINELID_TRUST_ANCHORS_FILE`.
    """
    self_signed_certificate(folder)
    path = folder / "anchors.json"
    path.write_text(
        json.dumps(
            [
                {
                    "issuer_id": "utopia",
                    "certificate": "issuer.pem",
                    "permitted_algorithms": ["RSA_PKCS1V15_SHA256"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def committed_text_files(suffixes: frozenset[str]) -> list[pathlib.Path]:
    """Return every file git tracks whose suffix is in `suffixes`.

    The repository scans that enforce rules 3 and 4 both describe themselves as
    covering "every committed text file". Walking the filesystem is not that: it
    also reads build output, tool caches and whatever a developer happens to
    have left in the tree. That made the suite's test count differ between one
    machine and a clean clone, and it meant a stray file could fail the build
    for reasons unrelated to the repository.

    Asking git makes the implementation mean what those docstrings say, and
    makes the count identical everywhere.

    Args:
        suffixes: File extensions worth scanning, including the leading dot.

    Returns:
        Absolute paths, sorted, of the tracked files that exist on disk.

    Raises:
        RuntimeError: If git cannot list the tree. The scans enforce two of
            CLAUDE.md's non-negotiable rules, so a scan that cannot establish
            what is committed fails rather than falling back to something
            weaker and calling it the same check.
    """
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z"],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        msg = (
            f"cannot ask git which files are committed, so the repository scans cannot run: {error}"
        )
        raise RuntimeError(msg) from error

    found: list[pathlib.Path] = []
    for name in listed.stdout.decode().split("\0"):
        if not name:
            continue
        path = REPO_ROOT / name
        if path.suffix in suffixes and path.is_file():
            found.append(path)
    return sorted(found)
