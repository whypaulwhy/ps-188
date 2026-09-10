"""The golden test harness: a fixture input, and the exact Evidence it must produce.

A golden case is a directory under `cases/` holding three files:

* `case.toml` — which detector the case is for, and the fixture's licence,
  provenance and digest;
* the input file named by `case.toml`;
* `expected.json` — a list of `Evidence` records, exactly as the detector must
  produce them.

Two fields are excluded from comparison, and only two. `runtime_ms` varies
between runs on the same machine. `model_version` changes when a detector is
versioned, which is not a change in behaviour and must not invalidate the whole
corpus at once. Everything else is compared exactly — including the officer-facing
text in `reasons`, so that wording cannot drift silently once it is committed.

Cases whose detector does not exist yet are reported as pending rather than
passing. They start running for real the moment the detector is registered,
without anything here changing.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography import x509

from core.contracts import (
    Artefact,
    DecodedCode,
    DocumentType,
    Evidence,
    Provenance,
    Subject,
    TextZone,
    ZoneName,
)
from detectors.rung0_crypto.trust_store import SignatureAlgorithm, TrustAnchor, TrustStore

HERE: Final[Path] = Path(__file__).parent
CASES_DIR: Final[Path] = HERE / "cases"
ANCHORS_DIR: Final[Path] = HERE / "anchors"
VECTORS_DIR: Final[Path] = HERE / "vectors"

FIXTURE_CAPTURED_AT: Final[datetime.datetime] = datetime.datetime(
    2026, 1, 1, 12, 0, tzinfo=datetime.UTC
)
"""A fixed capture time, so a subject built from a fixture is byte-for-byte reproducible."""

IGNORED_FIELDS: Final[frozenset[str]] = frozenset({"runtime_ms", "model_version"})
"""Fields excluded from golden comparison. See the module docstring for why these two."""

JARGON: Final[tuple[str, ...]] = (
    "check digit",
    "checksum",
    "mrz",
    "sha256",
    "hash",
    "pkcs",
    "verhoeff",
    "asn.1",
    "embedding",
    "inference",
    "heuristic",
    "confidence interval",
)
"""Words an officer at a barrier should never have to read. Enforced over `reasons`."""


@dataclass(frozen=True)
class GoldenCase:
    """One committed fixture and the exact output it pins."""

    case_id: str
    directory: Path
    description: str
    detector_id: str
    declared_type: DocumentType
    phase: int
    input_path: Path
    licence: str
    provenance: str
    declared_sha256: str
    anchors: tuple[str, ...]
    expected: tuple[Evidence, ...]

    def trust_store(self) -> TrustStore:
        """Build the trust store this case is screened against.

        Anchors are named in `case.toml` and loaded from `anchors/`. A case
        that names none is screened by a deployment holding no issuer keys,
        which is a legitimate and important state to test.
        """
        loaded: list[TrustAnchor] = []
        for name in self.anchors:
            der = (ANCHORS_DIR / name).read_bytes()
            certificate = x509.load_der_x509_certificate(der)
            loaded.append(
                TrustAnchor(
                    issuer_id=name.removesuffix(".der"),
                    public_key=certificate.public_key(),
                    permitted_algorithms=frozenset(
                        {
                            SignatureAlgorithm.RSA_PKCS1V15_SHA256,
                            SignatureAlgorithm.RSA_PSS_SHA256,
                        }
                    ),
                    not_before=certificate.not_valid_before_utc,
                    not_after=certificate.not_valid_after_utc,
                    certificate_der=der,
                )
            )
        return TrustStore(loaded)

    def actual_sha256(self) -> str:
        """Return the digest of the fixture file as it exists on disk."""
        return hashlib.sha256(self.input_path.read_bytes()).hexdigest()

    def subject(self) -> Subject:
        """Build the `Subject` a detector will be handed for this fixture.

        This stands in for the extraction pipeline, which does not exist until
        phase 6. It performs no recognition of its own: an `.mrz.txt` fixture
        becomes an MRZ zone holding exactly the lines in the file, and a
        `.fields.json` fixture becomes a visual inspection zone holding its
        printed fields. Nothing is repaired, and no zone is invented — a
        document with no strip simply has no MRZ zone, which is what makes the
        `NOT_APPLICABLE` cases meaningful.
        """
        data = self.input_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        suffixes = "".join(self.input_path.suffixes)

        zones: tuple[TextZone, ...] = ()
        codes: tuple[DecodedCode, ...] = ()
        if suffixes.endswith(".qr.txt"):
            # The bytes a code reader would hand over, verbatim. Signature
            # verification depends on them exactly, so the fixture holds the
            # payload and nothing here re-encodes or normalises it.
            media_type = "text/plain"
            codes = (DecodedCode(symbology="QR", payload=data.strip()),)
        elif suffixes.endswith(".mrz.txt"):
            media_type = "text/plain"
            zones = (
                TextZone(
                    name=ZoneName.MRZ,
                    lines=tuple(data.decode("utf-8").splitlines()),
                    complete=True,
                ),
            )
        elif suffixes.endswith(".fields.json"):
            media_type = "application/json"
            zones = (
                TextZone(
                    name=ZoneName.VISUAL_INSPECTION,
                    lines=_flatten(json.loads(data.decode("utf-8"))),
                    complete=True,
                ),
            )
        elif suffixes.endswith(".xml"):
            media_type = "application/xml"
        else:
            media_type = "application/pdf"

        return Subject(
            provenance=Provenance(
                source_id=self.case_id,
                sha256=digest,
                media_type=media_type,
                byte_size=len(data),
                captured_at=FIXTURE_CAPTURED_AT,
                received_at=FIXTURE_CAPTURED_AT,
                checkpoint_id="golden-corpus",
            ),
            declared_type=self.declared_type,
            artefacts=(
                Artefact(role="document_front", media_type=media_type, sha256=digest, data=data),
            ),
            zones=zones,
            codes=codes,
        )


def _flatten(value: Any, prefix: str = "") -> tuple[str, ...]:  # noqa: ANN401
    """Render a printed-field record as one `key: value` line per leaf.

    Args:
        value: The parsed record, or any nested part of it.
        prefix: The dotted path to this part.

    Returns:
        One line per leaf, in document order.
    """
    if isinstance(value, dict):
        lines: list[str] = []
        for key, nested in value.items():
            lines.extend(_flatten(nested, f"{prefix}.{key}" if prefix else str(key)))
        return tuple(lines)
    return (f"{prefix}: {value}",)


def load_case(directory: Path) -> GoldenCase:
    """Load one golden case from its directory.

    Args:
        directory: A directory containing `case.toml`, `expected.json` and the
            named input file.

    Returns:
        The parsed case, with `expected` already validated against the
        evidence contract.

    Raises:
        ValueError: If a required file or key is missing.
    """
    case_file = directory / "case.toml"
    expected_file = directory / "expected.json"
    for required in (case_file, expected_file):
        if not required.exists():
            msg = f"golden case {directory.name} is missing {required.name}"
            raise ValueError(msg)

    with case_file.open("rb") as handle:
        config: dict[str, Any] = tomllib.load(handle)

    for section in ("case", "fixture"):
        if section not in config:
            msg = f"golden case {directory.name} has no [{section}] section"
            raise ValueError(msg)

    case = config["case"]
    fixture = config["fixture"]
    expected_records: list[dict[str, Any]] = json.loads(expected_file.read_text(encoding="utf-8"))

    return GoldenCase(
        case_id=case["id"],
        directory=directory,
        description=case["description"],
        detector_id=case["detector"],
        declared_type=DocumentType(case["declared_type"]),
        phase=case["phase"],
        input_path=directory / case["input"],
        licence=fixture["licence"],
        provenance=fixture["provenance"],
        declared_sha256=fixture["sha256"],
        anchors=tuple(case.get("anchors", ())),
        expected=tuple(Evidence(**record) for record in expected_records),
    )


def discover_cases() -> tuple[GoldenCase, ...]:
    """Load every golden case, ordered by identifier.

    Returns:
        Every case under `cases/`, in a stable order.
    """
    return tuple(
        load_case(directory) for directory in sorted(CASES_DIR.iterdir()) if directory.is_dir()
    )


def load_vectors(name: str) -> dict[str, Any]:
    """Load a standards test vector file from `vectors/`.

    Args:
        name: File name, for example `verhoeff.json`.

    Returns:
        The parsed contents.
    """
    parsed: dict[str, Any] = json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))
    return parsed


def comparable(item: Evidence) -> dict[str, Any]:
    """Reduce evidence to the fields a golden case pins.

    Args:
        item: The evidence to reduce.

    Returns:
        Every field except those in :data:`IGNORED_FIELDS`.
    """
    dumped: dict[str, Any] = item.model_dump(mode="json")
    return {key: value for key, value in dumped.items() if key not in IGNORED_FIELDS}


def differences(actual: tuple[Evidence, ...], expected: tuple[Evidence, ...]) -> list[str]:
    """Describe every way actual output departs from a golden expectation.

    Args:
        actual: What the detector produced.
        expected: What the golden case requires.

    Returns:
        One readable line per difference. Empty if the two match.
    """
    problems: list[str] = []

    if len(actual) != len(expected):
        problems.append(
            f"expected {len(expected)} piece(s) of evidence, detector produced {len(actual)}"
        )

    for index, (produced, required) in enumerate(zip(actual, expected, strict=False)):
        left = comparable(produced)
        right = comparable(required)
        for field in sorted(set(left) | set(right)):
            if left.get(field) != right.get(field):
                problems.append(
                    f"evidence[{index}].{field}: expected {right.get(field)!r}, "
                    f"got {left.get(field)!r}"
                )

    return problems


def assert_matches(
    actual: tuple[Evidence, ...], expected: tuple[Evidence, ...], *, case_id: str
) -> None:
    """Fail with a readable report unless actual output matches the golden exactly.

    Args:
        actual: What the detector produced.
        expected: What the golden case requires.
        case_id: Named in the failure message.

    Raises:
        AssertionError: If the two differ on any compared field.
    """
    problems = differences(actual, expected)
    if problems:
        report = "\n  ".join(problems)
        msg = f"golden case {case_id} does not match:\n  {report}"
        raise AssertionError(msg)
