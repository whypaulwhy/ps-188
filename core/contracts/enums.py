"""The closed vocabularies used across the evidence contract.

Nothing in this module has behaviour beyond membership and ordering. The
meaning of each value is fixed here so that a rung, a result or a decision
means exactly one thing everywhere in the system, including in the audit log
years after a case was screened.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final


class Rung(IntEnum):
    """The trust rung a detector declares.

    The numeric value is the rung's position on the ladder, counted from the
    top. **A smaller number means more authority**, so ``Rung.CRYPTOGRAPHIC``
    (0) outranks ``Rung.CONTEXTUAL`` (3). Comparisons therefore read
    backwards from intuition on purpose: ``Rung.CRYPTOGRAPHIC < Rung.INFERENCE``
    is true and means "cryptographic proof outranks inference".

    A detector may never declare a rung more authoritative than the evidence it
    actually produces. A model that outputs a probability is Rung 2 even if it
    is very accurate.
    """

    CRYPTOGRAPHIC = 0
    """Issuer signature verified with public key cryptography. Proof, not opinion."""

    DETERMINISTIC = 1
    """Arithmetic or logic fixed by a published standard. Reproducible by hand."""

    INFERENCE = 2
    """A learned model produced a score. May escalate a case, never clear one."""

    CONTEXTUAL = 3
    """Information about history or watchlists. Advisory to the officer only."""


class Result(StrEnum):
    """The categorical outcome a detector reports.

    Each rung has its own permitted subset, given by :data:`RESULTS_BY_RUNG`.
    The subsets do not overlap, so a result value alone tells you which rung
    produced it. This is deliberate: it makes it impossible for a Rung 2
    detector to report ``PROOF_VALID`` and have it silently believed.
    """

    # Rung 0, cryptographic.
    PROOF_VALID = "PROOF_VALID"
    """A signature over the document data verified against a trusted issuer key."""

    PROOF_INVALID = "PROOF_INVALID"
    """A signature was present and failed to verify. The document is not genuine."""

    NO_PROOF_PRESENT = "NO_PROOF_PRESENT"
    """No signature was found to verify. Says nothing about authenticity."""

    # Rung 1, deterministic.
    PASS = "PASS"  # noqa: S105 - a check outcome, not a credential
    """The document conforms to the standard this detector checks."""

    FAIL = "FAIL"
    """The document violates the standard this detector checks."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    """This standard does not govern this document type. Not a pass."""

    # Rung 2, inference.
    NO_FINDING = "NO_FINDING"
    """The model ran and raised nothing. This is not evidence of authenticity."""

    SUSPICIOUS = "SUSPICIOUS"
    """The model ran and raised a concern that a human should look at."""

    INCONCLUSIVE = "INCONCLUSIVE"
    """The model could not produce a usable answer, or was unavailable."""

    # Rung 3, contextual.
    FLAG_RAISED = "FLAG_RAISED"
    """A contextual signal the officer should know about. Never decides."""

    NO_FLAG = "NO_FLAG"
    """The context was checked and there is nothing to report. Never decides."""

    NOT_CHECKED = "NOT_CHECKED"
    """The context could not be checked at all. Establishes nothing, and says so.

    Added because the alternative was worse. Without it, a watchlist that could
    not be consulted -- no list loaded, or a document whose number could not be
    read -- would have to report ``NO_FLAG``, which an officer reads as "checked,
    nothing found". Silence about a check that did not happen is a defect, not a
    clean result, so this lands in ``Verdict.not_checked`` alongside
    ``NO_PROOF_PRESENT`` and ``INCONCLUSIVE``.
    """


class Decision(StrEnum):
    """The disposition of a whole screening case.

    There is no fourth value. Anything that is not proven genuine and not
    proven bad goes to a human.
    """

    CLEARED = "CLEARED"
    """Positively established. The traveller may proceed on this document."""

    MANUAL_REVIEW = "MANUAL_REVIEW"
    """Not established either way. An officer decides. This is the safe default."""

    REJECTED = "REJECTED"
    """Positively disproven. The document failed a check that cannot be argued with."""


class Severity(IntEnum):
    """How loudly a finding should be presented to the officer.

    Ordered, so a console can sort by it. Higher means more serious.
    """

    INFO = 0
    """A check that passed, recorded so the officer can see what was done."""

    ADVISORY = 1
    """Contextual information. Carries no weight in the decision."""

    CONCERN = 2
    """Something a human needs to look at before this document is accepted."""

    CRITICAL = 3
    """A check that cannot be argued with has failed."""


RESULTS_BY_RUNG: Final[Mapping[Rung, frozenset[Result]]] = MappingProxyType(
    {
        Rung.CRYPTOGRAPHIC: frozenset(
            {Result.PROOF_VALID, Result.PROOF_INVALID, Result.NO_PROOF_PRESENT}
        ),
        Rung.DETERMINISTIC: frozenset({Result.PASS, Result.FAIL, Result.NOT_APPLICABLE}),
        Rung.INFERENCE: frozenset({Result.NO_FINDING, Result.SUSPICIOUS, Result.INCONCLUSIVE}),
        Rung.CONTEXTUAL: frozenset({Result.FLAG_RAISED, Result.NO_FLAG, Result.NOT_CHECKED}),
    }
)
"""Which results each rung may report. Enforced by the Evidence contract."""


SCORED_RUNGS: Final[frozenset[Rung]] = frozenset({Rung.INFERENCE})
"""The only rungs permitted to attach a numeric score. Rung 0 and 1 are proof, not probability."""
