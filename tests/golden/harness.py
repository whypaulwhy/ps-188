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

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from core.contracts import Evidence

HERE: Final[Path] = Path(__file__).parent
CASES_DIR: Final[Path] = HERE / "cases"
VECTORS_DIR: Final[Path] = HERE / "vectors"

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
    phase: int
    input_path: Path
    licence: str
    provenance: str
    declared_sha256: str
    expected: tuple[Evidence, ...]

    def actual_sha256(self) -> str:
        """Return the digest of the fixture file as it exists on disk."""
        return hashlib.sha256(self.input_path.read_bytes()).hexdigest()

    def subject(self) -> bytes:
        """Return the fixture as the bytes a detector will be handed.

        Phase 0 and 1 have no extraction contract, so a subject is raw bytes.
        When phase 2 defines what a detector actually receives — the normalised
        image, the located zones, the decoded payloads — this method is the one
        place that changes.
        """
        return self.input_path.read_bytes()


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
        phase=case["phase"],
        input_path=directory / case["input"],
        licence=fixture["licence"],
        provenance=fixture["provenance"],
        declared_sha256=fixture["sha256"],
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
