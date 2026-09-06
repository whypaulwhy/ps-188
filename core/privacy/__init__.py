"""Hashing, masking and retention rules that keep raw identifiers out of storage.

The shape of the thing: a document number enters as a
:class:`~core.privacy.identifiers.RawIdentifier`, which masks itself everywhere
except one deliberate method. The only route from there to something storable
is :func:`~core.privacy.hashing.hash_document_number`. Nothing else in the
system should ever hold a number in the clear, and nothing at all should
persist one.
"""

from __future__ import annotations

from core.privacy.hashing import (
    DIGEST_LENGTH,
    MINIMUM_KEY_BYTES,
    DeploymentKey,
    digests_match,
    hash_document_number,
)
from core.privacy.identifiers import IdentifierKind, RawIdentifier
from core.privacy.masking import mask_aadhaar, mask_value
from core.privacy.retention import (
    ArtefactCategory,
    RetentionPolicy,
    deletion_due_at,
    is_due_for_deletion,
)

__all__ = [
    "DIGEST_LENGTH",
    "MINIMUM_KEY_BYTES",
    "ArtefactCategory",
    "DeploymentKey",
    "IdentifierKind",
    "RawIdentifier",
    "RetentionPolicy",
    "deletion_due_at",
    "digests_match",
    "hash_document_number",
    "is_due_for_deletion",
    "mask_aadhaar",
    "mask_value",
]
