"""Storing a face embedding, which is personal data and not a hash.

**A face embedding is not anonymous.** It can be partially inverted: given the
vector and the model that produced it, an approximation of the face can be
reconstructed. It is therefore biometric personal data, and this module exists
because storing it as a bare list of floats — the obvious implementation —
treats it as though it were a checksum.

Rule 4 of CLAUDE.md forbids describing an embedding as irreversible, one-way or
PII-free anywhere in this repository. A test enforces that across every file,
because the claim is exactly the kind that gets written into a slide by someone
who read the code quickly.

Three things follow, and all three are enforced by the types rather than by
review.

**It is encrypted at rest.** An embedding leaves this module only as
`EncryptedEmbedding`, which carries ciphertext. There is no path that persists
the vector in the clear, because nothing accepts one.

**The key is separate from the identifier hashing key.** Biometric data and
document-number digests have different retention windows, different sensitivity
and different reasons to be rotated. Sharing one key would mean compromising
either compromises both, and rotating for one forces rotating for the other.
See ADR 0005 for the identifier side.

**It carries its own age.** `created_at` is inside the record and inside the
authenticated data, so a retention window can be enforced against it and the
timestamp cannot be edited to extend the window without the ciphertext failing
to decrypt.

The model version is bound into the ciphertext for the same reason: a record
produced by one model cannot be silently reinterpreted under another, which
would compare vectors that were never comparable.
"""

from __future__ import annotations

import array
import datetime
import secrets
from typing import Annotated, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.privacy.retention import ArtefactCategory, RetentionPolicy, is_due_for_deletion

KEY_BYTES: Final[int] = 32
"""AES-256. Shorter keys are refused outright rather than accepted with a warning."""

NONCE_BYTES: Final[int] = 12
"""Standard AES-GCM nonce length. A fresh one is generated for every record."""


class BiometricKeyError(ValueError):
    """The biometric key is missing, too short, or cannot decrypt this record."""


class BiometricKey:
    """The per-deployment secret that encrypts face embeddings at rest.

    Deliberately a different type from
    :class:`~core.privacy.hashing.DeploymentKey`, so the two cannot be passed
    to each other's functions by mistake, and deliberately a different secret,
    so compromising one does not compromise the other.
    """

    __slots__ = ("_material",)

    def __init__(self, material: bytes) -> None:
        """Hold key material.

        Args:
            material: Exactly :data:`KEY_BYTES` bytes from a secure source.

        Raises:
            BiometricKeyError: If the material is the wrong length.
        """
        if len(material) != KEY_BYTES:
            msg = f"a biometric key must be exactly {KEY_BYTES} bytes"
            raise BiometricKeyError(msg)
        self._material = material

    @classmethod
    def generate(cls) -> BiometricKey:
        """Return a new key from the system's secure random source.

        Returns:
            A fresh key. Losing it makes every stored embedding unreadable,
            which is a deletion mechanism as well as a risk.
        """
        return cls(secrets.token_bytes(KEY_BYTES))

    def _cipher(self) -> AESGCM:
        """Return the cipher. The key material never leaves this object."""
        return AESGCM(self._material)

    def __repr__(self) -> str:
        """Return a redacted form, so a key never reaches a traceback or a log."""
        return "BiometricKey(<redacted>)"

    __str__ = __repr__


class EncryptedEmbedding(BaseModel):
    """A face embedding as it may be stored: encrypted, dated and attributed.

    Immutable. There is no field holding the vector in the clear, and no way to
    construct one that does.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ciphertext: bytes
    """The encrypted vector. Meaningless without the deployment's biometric key."""

    nonce: Annotated[bytes, Field(min_length=NONCE_BYTES, max_length=NONCE_BYTES)]
    """Unique per record. Reusing one with the same key would destroy the encryption."""

    created_at: datetime.datetime
    """When the embedding was produced. Bound into the ciphertext, so it cannot be edited."""

    model_version: Annotated[str, Field(min_length=1, max_length=128)]
    """Which model produced the vector. Also bound in: two models are not comparable."""

    dimension: Annotated[int, Field(gt=0)]
    """How many components the vector had. Metadata only; it reveals nothing about the face."""

    @field_validator("created_at")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime.datetime) -> datetime.datetime:
        """Reject a naive timestamp, which cannot be aged against a retention window."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = "created_at must be timezone aware"
            raise ValueError(msg)
        return value

    def _associated_data(self) -> bytes:
        """Return the fields bound into the ciphertext but not hidden by it."""
        return f"{self.model_version}|{self.created_at.isoformat()}|{self.dimension}".encode()

    def is_due_for_deletion(self, *, policy: RetentionPolicy, now: datetime.datetime) -> bool:
        """Report whether this embedding has outlived its retention window.

        Args:
            policy: The deployment's retention policy. It cannot be constructed
                without an explicit window for face embeddings.
            now: The instant to judge against.

        Returns:
            Whether the record must be destroyed.
        """
        return is_due_for_deletion(
            self.created_at,
            category=ArtefactCategory.FACE_EMBEDDING,
            policy=policy,
            now=now,
        )


def encrypt_embedding(
    vector: tuple[float, ...],
    *,
    key: BiometricKey,
    created_at: datetime.datetime,
    model_version: str,
) -> EncryptedEmbedding:
    """Encrypt a face embedding for storage.

    The only way to obtain a storable embedding. Nothing in this project
    persists the vector itself.

    Args:
        vector: The embedding as produced by the model.
        key: The deployment's biometric key.
        created_at: When the embedding was produced. Must carry a timezone.
        model_version: Which model produced it.

    Returns:
        The encrypted record.

    Raises:
        BiometricKeyError: If the vector is empty. An empty embedding is a bug
            upstream, and storing one would be a record that decrypts to
            nothing.
    """
    if not vector:
        msg = "an empty embedding cannot be stored"
        raise BiometricKeyError(msg)

    nonce = secrets.token_bytes(NONCE_BYTES)
    record = EncryptedEmbedding(
        ciphertext=b"",
        nonce=nonce,
        created_at=created_at,
        model_version=model_version,
        dimension=len(vector),
    )
    plaintext = array.array("d", vector).tobytes()
    # Reaching into both objects on purpose: the key material must not leave
    # BiometricKey, and the authenticated data is derived from the record.
    ciphertext = key._cipher().encrypt(nonce, plaintext, record._associated_data())
    return record.model_copy(update={"ciphertext": ciphertext})


def decrypt_embedding(record: EncryptedEmbedding, *, key: BiometricKey) -> tuple[float, ...]:
    """Recover an embedding for comparison.

    Args:
        record: The stored record.
        key: The deployment's biometric key.

    Returns:
        The vector.

    Raises:
        BiometricKeyError: If the key is wrong, or the record has been altered.
            Editing `created_at` to extend a retention window breaks
            decryption, because the timestamp is authenticated.
    """
    try:
        plaintext = key._cipher().decrypt(
            record.nonce, record.ciphertext, record._associated_data()
        )
    except InvalidTag as error:
        msg = "this embedding cannot be decrypted with that key, or it has been altered"
        raise BiometricKeyError(msg) from error

    recovered = array.array("d")
    recovered.frombytes(plaintext)
    return tuple(recovered)
