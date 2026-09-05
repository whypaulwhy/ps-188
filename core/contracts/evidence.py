"""The unit of output every detector produces.

No detector in SENTINEL ID returns a bare ``bool``, ``float`` or ``str``. It
returns :class:`Evidence`, which carries not only what was found but what rung
of trust the finding sits on, what standard makes it defensible, how long it
took, and which model version produced it.

The class enforces the rules of the trust ladder structurally, so a detector
cannot overstate its own authority even by accident:

* a result value belongs to exactly one rung, so Rung 2 cannot report ``PROOF_VALID``;
* only Rung 2 may attach a score, so proof can never be diluted into a probability;
* Rung 0 and Rung 1 must cite the standard they applied.
"""

from __future__ import annotations

import re
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.contracts.enums import RESULTS_BY_RUNG, SCORED_RUNGS, Result, Rung

SHA256_HEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
"""Lowercase hex SHA-256, matching :data:`core.contracts.provenance.SHA256_HEX`."""

DETECTOR_ID: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
"""Dotted lowercase identifier, for example ``rung1.mrz_checkdigits``."""

UNSCORED_RESULTS: Final[frozenset[Result]] = frozenset({Result.INCONCLUSIVE})
"""Rung 2 results that must not carry a number, because there is no answer to put in one."""


class Evidence(BaseModel):
    """One detector's finding about one artefact, with everything needed to defend it.

    Immutable. Constructing an ``Evidence`` that violates the trust ladder
    raises :class:`pydantic.ValidationError` rather than producing a value that
    later code has to be careful with.

    On ``score``: it is **suspicion**, not authenticity. ``0.0`` means the
    detector saw nothing wrong and ``1.0`` means the detector is as alarmed as
    it can be. The direction is fixed this way so that a larger number can only
    ever make a case worse, which is what rule 1 of CLAUDE.md requires. A Rung 2
    detector has no way to express "this document is genuine", because it has no
    standing to say so.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    detector_id: Annotated[str, Field(min_length=1, max_length=128)]
    """Stable dotted identifier of the detector, unique across the registry."""

    rung: Rung
    """The trust rung this detector declares. Fixes what it is allowed to say."""

    result: Result
    """The categorical outcome. Must belong to this rung's permitted set."""

    score: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    """Suspicion in [0, 1], Rung 2 only. Higher is worse. Never a probability of authenticity."""

    uncertainty: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    """How little the detector trusts its own score, in [0, 1]. Rung 2 only."""

    reasons: Annotated[tuple[str, ...], Field(min_length=1)]
    """What the officer reads. Plain language, no jargon, no check-digit talk."""

    standard_ref: Annotated[str | None, Field(max_length=256)] = None
    """The clause applied, e.g. ``ICAO Doc 9303 Part 3 s.4.2.2``. Required at Rung 0 and 1."""

    artifacts: tuple[str, ...] = ()
    """Repository-relative paths to heatmaps, crops or decoded payloads kept as exhibits."""

    runtime_ms: Annotated[float, Field(ge=0.0)]
    """Wall-clock milliseconds this detector spent on this artefact."""

    model_version: Annotated[str, Field(min_length=1, max_length=128)]
    """Version of whatever produced this: model weights at Rung 2, detector code elsewhere."""

    input_digest: Annotated[str, Field(min_length=64, max_length=64)]
    """Lowercase hex SHA-256 of the exact bytes this detector examined."""

    @field_validator("detector_id")
    @classmethod
    def _detector_id_is_well_formed(cls, value: str) -> str:
        """Reject identifiers that will not survive being used as a log key."""
        if not DETECTOR_ID.match(value):
            msg = "detector_id must be a dotted lowercase identifier"
            raise ValueError(msg)
        return value

    @field_validator("input_digest")
    @classmethod
    def _digest_is_lowercase_hex(cls, value: str) -> str:
        """Reject anything that is not a lowercase hex SHA-256 digest."""
        if not SHA256_HEX.match(value):
            msg = "input_digest must be 64 lowercase hexadecimal characters"
            raise ValueError(msg)
        return value

    @field_validator("reasons")
    @classmethod
    def _reasons_are_readable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject blank reasons; an officer cannot act on an empty string."""
        for reason in value:
            if not reason.strip():
                msg = "every reason must contain text"
                raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _result_belongs_to_rung(self) -> Evidence:
        """Reject a result the declared rung is not entitled to report."""
        if self.result not in RESULTS_BY_RUNG[self.rung]:
            msg = f"result {self.result} is not permitted at {self.rung.name}"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _only_inference_carries_numbers(self) -> Evidence:
        """Reject scores outside Rung 2, where they would dress proof up as probability."""
        carries_numbers = self.score is not None or self.uncertainty is not None
        if self.rung not in SCORED_RUNGS and carries_numbers:
            msg = f"{self.rung.name} evidence must not carry a score or uncertainty"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _inference_numbers_match_result(self) -> Evidence:
        """Reject Rung 2 evidence whose numbers contradict its own result."""
        if self.rung not in SCORED_RUNGS:
            return self
        if self.result in UNSCORED_RESULTS:
            if self.score is not None or self.uncertainty is not None:
                msg = "an inconclusive result must not carry a score or uncertainty"
                raise ValueError(msg)
            return self
        if self.score is None or self.uncertainty is None:
            msg = "a conclusive Rung 2 result requires both a score and an uncertainty"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _authoritative_rungs_cite_a_standard(self) -> Evidence:
        """Reject Rung 0 or Rung 1 evidence that cites nothing, since it decides cases."""
        if self.rung in (Rung.CRYPTOGRAPHIC, Rung.DETERMINISTIC) and not self.standard_ref:
            msg = f"{self.rung.name} evidence must cite a standard_ref"
            raise ValueError(msg)
        return self
