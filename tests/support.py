"""Factories for building valid contract objects in tests.

Every helper here produces a *valid* object by default, so a test that wants to
exercise a rejection can override exactly one field and the reader can see
immediately what is being tested.
"""

from __future__ import annotations

import datetime
from typing import Any, Final

from core.contracts import Evidence, Provenance, Result, Rung

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
