"""Where the material under examination came from.

Provenance answers the question an auditor asks first: *what exactly was
screened, and how did it reach the system?* It is recorded once per case and
carried on the verdict, so a decision can be tied back to a specific set of
bytes and a specific capture event.
"""

from __future__ import annotations

import datetime
import re
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SHA256_HEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
"""Lowercase hex SHA-256. Digests are compared as strings, so the case is pinned."""


class Provenance(BaseModel):
    """The origin and identity of one captured artefact.

    Immutable once constructed. Every field is either observed at capture time
    or computed from the captured bytes; nothing here is inferred by a model.

    Note that ``sha256`` is the digest of the artefact *as received*, before any
    normalisation. Preprocessing steps that alter pixels are recorded in
    ``processing_chain`` so that a later reviewer can tell whether a detector
    saw the original bytes or a derived image.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: Annotated[str, Field(min_length=1, max_length=128)]
    """Opaque case-local identifier for this artefact. Never a document number."""

    sha256: Annotated[str, Field(min_length=64, max_length=64)]
    """Lowercase hex SHA-256 of the artefact exactly as received."""

    media_type: Annotated[str, Field(min_length=3, max_length=128)]
    """IANA media type of the artefact, for example ``image/jpeg``."""

    byte_size: Annotated[int, Field(ge=0)]
    """Size of the artefact in bytes as received."""

    captured_at: datetime.datetime
    """When the artefact was produced at the checkpoint. Must carry a timezone."""

    received_at: datetime.datetime
    """When the system took custody of the artefact. Must carry a timezone."""

    checkpoint_id: Annotated[str, Field(min_length=1, max_length=64)]
    """Which checkpoint captured this. Used for jurisdiction and retention rules."""

    capture_device: Annotated[str | None, Field(max_length=128)] = None
    """Scanner or camera identifier, when the capture path reports one."""

    processing_chain: tuple[str, ...] = ()
    """Ordered names of transformations applied before detectors saw the artefact."""

    @field_validator("sha256")
    @classmethod
    def _digest_is_lowercase_hex(cls, value: str) -> str:
        """Reject anything that is not a lowercase hex SHA-256 digest."""
        if not SHA256_HEX.match(value):
            msg = "sha256 must be 64 lowercase hexadecimal characters"
            raise ValueError(msg)
        return value

    @field_validator("captured_at", "received_at")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime.datetime) -> datetime.datetime:
        """Reject naive timestamps, which are unusable in an audit record."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = "timestamps must be timezone aware"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _custody_is_ordered(self) -> Provenance:
        """Reject a record that claims custody before capture."""
        if self.received_at < self.captured_at:
            msg = "received_at cannot precede captured_at"
            raise ValueError(msg)
        return self
