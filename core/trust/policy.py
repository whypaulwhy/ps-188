"""The tables the trust ladder resolves against.

Keeping these out of :mod:`core.trust.ladder` means the policy can be read,
reviewed and argued about on its own, without reading control flow. Every
entry is a ``(rung, result)`` pair, so a change here cannot accidentally give a
rung an authority it was never granted.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from core.contracts import Decision, Result, Rung, Severity

POLICY_VERSION: Final[str] = "fail-closed/1"
"""Identifies the resolution rules below. Recorded on every verdict so old cases stay readable."""

DECISION_SEVERITY: Final[Mapping[Decision, int]] = MappingProxyType(
    {
        Decision.CLEARED: 0,
        Decision.MANUAL_REVIEW: 1,
        Decision.REJECTED: 2,
    }
)
"""Total order on outcomes, worst last. Used to state and test monotonicity."""

REJECTING: Final[frozenset[tuple[Rung, Result]]] = frozenset(
    {
        (Rung.CRYPTOGRAPHIC, Result.PROOF_INVALID),
        (Rung.DETERMINISTIC, Result.FAIL),
    }
)
"""Evidence that ends the case. Only the two authoritative rungs appear here."""

ESCALATING: Final[frozenset[tuple[Rung, Result]]] = frozenset(
    {
        (Rung.INFERENCE, Result.SUSPICIOUS),
    }
)
"""Evidence that forces a human to look. It can never do more, and never less."""

PROVING: Final[frozenset[tuple[Rung, Result]]] = frozenset(
    {
        (Rung.CRYPTOGRAPHIC, Result.PROOF_VALID),
    }
)
"""Evidence that can clear a document. Cryptographic proof of issuance and nothing else."""

SILENT: Final[frozenset[tuple[Rung, Result]]] = frozenset(
    {
        (Rung.CRYPTOGRAPHIC, Result.NO_PROOF_PRESENT),
        (Rung.DETERMINISTIC, Result.NOT_APPLICABLE),
        (Rung.INFERENCE, Result.INCONCLUSIVE),
        (Rung.CONTEXTUAL, Result.NOT_CHECKED),
    }
)
"""Evidence that establishes nothing. Each one becomes a line in ``Verdict.not_checked``."""

ADVISORY: Final[frozenset[tuple[Rung, Result]]] = frozenset(
    {
        (Rung.CONTEXTUAL, Result.FLAG_RAISED),
    }
)
"""Context the officer should see. Filed separately from findings so it cannot sway a decision."""

FindingTemplate = tuple[str, Severity, str]
"""The code, severity and headline a result becomes on the officer console."""

FINDING_TEMPLATES: Final[Mapping[tuple[Rung, Result], FindingTemplate]] = MappingProxyType(
    {
        (Rung.CRYPTOGRAPHIC, Result.PROOF_VALID): (
            "ISSUER_SIGNATURE_VALID",
            Severity.INFO,
            "The issuing authority's digital signature on this document is genuine.",
        ),
        (Rung.CRYPTOGRAPHIC, Result.PROOF_INVALID): (
            "ISSUER_SIGNATURE_INVALID",
            Severity.CRITICAL,
            "This document carries an official signature that does not match "
            "what is printed on it.",
        ),
        (Rung.DETERMINISTIC, Result.PASS): (
            "STANDARD_CHECK_PASSED",
            Severity.INFO,
            "The document follows the official layout and numbering rules for its type.",
        ),
        (Rung.DETERMINISTIC, Result.FAIL): (
            "STANDARD_CHECK_FAILED",
            Severity.CRITICAL,
            "The document breaks a fixed rule that every genuine document of this type follows.",
        ),
        (Rung.INFERENCE, Result.NO_FINDING): (
            "NO_ALTERATION_SIGNAL",
            Severity.INFO,
            "An automated check for signs of alteration raised nothing. "
            "This is not proof that the document is genuine.",
        ),
        (Rung.INFERENCE, Result.SUSPICIOUS): (
            "POSSIBLE_ALTERATION",
            Severity.CONCERN,
            "An automated check noticed something unusual that a person should look at.",
        ),
        (Rung.CONTEXTUAL, Result.FLAG_RAISED): (
            "CONTEXT_FLAG",
            Severity.ADVISORY,
            "Background information for your attention. It did not affect this decision.",
        ),
    }
)
"""Code, severity and plain-language headline for every result that becomes a finding.

Results absent from this table produce no finding: the three ``SILENT`` pairs
become ``not_checked`` lines instead, and ``NO_FLAG`` is simply nothing to say.
"""


def decision_severity(decision: Decision) -> int:
    """Return the position of a decision in the worst-last ordering.

    Args:
        decision: The outcome to rank.

    Returns:
        ``0`` for ``CLEARED``, ``1`` for ``MANUAL_REVIEW``, ``2`` for ``REJECTED``.
    """
    return DECISION_SEVERITY[decision]
