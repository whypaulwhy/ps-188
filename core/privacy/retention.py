"""How long each kind of stored artefact may be kept.

Rule 4 of CLAUDE.md requires retention limits on face embeddings, and the same
question applies to every other thing a screening produces. This module makes
the answer explicit and refuses to let it be implicit.

**There are no default windows.** A :class:`RetentionPolicy` will not construct
unless every category has been given one. That is deliberate: shipping
defaults would put invented day counts into the repository where they would be
read as policy, and defaults survive into production unexamined. The system
does not start until somebody decides, which is the point.

There is also no unbounded window. An operator who wants to keep the audit
ledger indefinitely states a large explicit number, so the decision is visible
in configuration rather than absent from it.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator


class ArtefactCategory(StrEnum):
    """A kind of stored thing, each with its own retention window."""

    FACE_EMBEDDING = "FACE_EMBEDDING"
    """Biometric data. Partially invertible, so never described as anonymous."""

    PORTRAIT_CROP = "PORTRAIT_CROP"
    """The face region cut from a document or a live capture."""

    DOCUMENT_IMAGE = "DOCUMENT_IMAGE"
    """The captured document as received."""

    EVIDENCE_EXHIBIT = "EVIDENCE_EXHIBIT"
    """Heatmaps, crops and decoded payloads referenced by a finding."""

    CASE_RECORD = "CASE_RECORD"
    """The verdict and its evidence. Holds digests, never raw numbers."""

    LEDGER_ENTRY = "LEDGER_ENTRY"
    """The append-only audit trail entry for a decision."""


class RetentionPolicy(BaseModel):
    """The retention window for every artefact category.

    Immutable. Construction fails unless the policy is complete, so a
    deployment cannot start with an unanswered question about biometrics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    windows: Mapping[ArtefactCategory, datetime.timedelta]
    """How long each category may be kept, from creation."""

    @model_validator(mode="after")
    def _every_category_is_covered(self) -> RetentionPolicy:
        """Reject a policy that leaves any category unanswered."""
        missing = sorted(
            category.value for category in ArtefactCategory if category not in self.windows
        )
        if missing:
            msg = f"no retention window given for {', '.join(missing)}"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _every_window_is_positive(self) -> RetentionPolicy:
        """Reject a window of zero or less, which is a policy nobody can act on."""
        for category, window in self.windows.items():
            if window <= datetime.timedelta(0):
                msg = f"the retention window for {category.value} must be positive"
                raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _biometrics_do_not_outlive_the_case(self) -> RetentionPolicy:
        """Reject a policy keeping face data longer than the case that justified it.

        Rule 4 of CLAUDE.md treats a face embedding as personal data. Holding
        one after the case record it belongs to has been destroyed leaves
        biometric data with nothing to account for it.
        """
        if (
            self.windows[ArtefactCategory.FACE_EMBEDDING]
            > self.windows[ArtefactCategory.CASE_RECORD]
        ):
            msg = "face embeddings cannot be kept longer than the case record they belong to"
            raise ValueError(msg)
        return self


def deletion_due_at(
    created_at: datetime.datetime, *, category: ArtefactCategory, policy: RetentionPolicy
) -> datetime.datetime:
    """Return the instant at which an artefact must be destroyed.

    Args:
        created_at: When the artefact was produced. Must carry a timezone.
        category: What kind of artefact it is.
        policy: The deployment's retention policy.

    Returns:
        The deletion deadline.

    Raises:
        ValueError: If `created_at` is naive, which cannot be placed on a
            timeline and so cannot be aged.
    """
    if created_at.tzinfo is None or created_at.tzinfo.utcoffset(created_at) is None:
        msg = "created_at must be timezone aware"
        raise ValueError(msg)
    return created_at + policy.windows[category]


def is_due_for_deletion(
    created_at: datetime.datetime,
    *,
    category: ArtefactCategory,
    policy: RetentionPolicy,
    now: datetime.datetime,
) -> bool:
    """Report whether an artefact has passed its retention window.

    Args:
        created_at: When the artefact was produced.
        category: What kind of artefact it is.
        policy: The deployment's retention policy.
        now: The instant to judge against, passed in so this stays a pure
            function and a decision can be replayed.

    Returns:
        Whether the artefact is due for destruction.

    Raises:
        ValueError: If either timestamp is naive.
    """
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        msg = "now must be timezone aware"
        raise ValueError(msg)
    return now >= deletion_due_at(created_at, category=category, policy=policy)
