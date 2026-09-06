"""What a deployment has to tell the system before it will run.

Three values have no safe default, so there is none: the database, the identity
of the checkpoint, and where the keys live. Inventing any of them produces a
system that runs and is wrong — a second database nobody knows about, an audit
record stamped with the wrong crossing, or a checkpoint signed by a key that
was generated at start-up and proves nothing.

**Keys are read from files, not environment variables.** An environment
variable is visible to anything that can read `/proc`, is captured by
`docker inspect`, and lands in a crash dump. A file can be mounted read-only
and owned by one user. Both keys must live outside the database, per
[ADR 0005](../docs/adr/0005-keyed-hashing-for-document-numbers.md), and a file
is the form that makes that true in practice.

**A missing key degrades a capability; it never fakes one.** With no signing
key the checkpoint endpoint refuses and says why. Generating an ephemeral key
so the endpoint returns something would be worse than the refusal: a signature
nobody can verify against a published key is decoration, and it would read as
proof.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from core.privacy.hashing import DeploymentKey

DATABASE_URL: Final[str] = "SENTINELID_DB_URL"
CHECKPOINT_ID: Final[str] = "SENTINELID_CHECKPOINT_ID"
HASH_KEY_FILE: Final[str] = "SENTINELID_HASH_KEY_FILE"
LEDGER_KEY_FILE: Final[str] = "SENTINELID_LEDGER_KEY_FILE"
MAX_UPLOAD_BYTES: Final[str] = "SENTINELID_MAX_UPLOAD_BYTES"

DEFAULT_MAX_UPLOAD_BYTES: Final[int] = 15 * 1024 * 1024
"""A cap on one capture. A policy limit, not a measurement of anything."""

NO_LEDGER_KEY: Final[str] = (
    "This checkpoint holds no signing key, so no ledger checkpoint can be published "
    "and no third party can yet verify these records."
)
NO_HASH_KEY: Final[str] = (
    "This checkpoint holds no hashing key, so repeat-crossing and watchlist checks "
    "were not consulted."
)


class ConfigurationError(RuntimeError):
    """The deployment did not supply something that has no safe default."""


@dataclasses.dataclass(frozen=True)
class Settings:
    """Everything the shell needs, and an honest account of what is missing."""

    database_url: str
    """Where case records and ledger leaves are written."""

    checkpoint_id: str
    """Which crossing this is. Stamped on every audit record."""

    hash_key: DeploymentKey | None = None
    """Derives identifier digests. Without it, Rung 3 cannot run at all."""

    ledger_key: Ed25519PrivateKey | None = None
    """Signs transparency-log checkpoints. Without it, none can be published."""

    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    """Largest accepted capture."""

    def unavailable(self) -> tuple[str, ...]:
        """Return what this deployment cannot do, in sentences an officer reads.

        Returns:
            One sentence per absent capability, empty if nothing is missing.
            These reach the officer rather than a log file, because a capability
            that is quietly absent is the failure mode CLAUDE.md calls a defect.
        """
        missing: list[str] = []
        if self.ledger_key is None:
            missing.append(NO_LEDGER_KEY)
        if self.hash_key is None:
            missing.append(NO_HASH_KEY)
        return tuple(missing)


def _required(name: str) -> str:
    """Read an environment variable that has no safe default."""
    value = os.environ.get(name, "").strip()
    if not value:
        msg = f"{name} is not set, and there is no safe default for it"
        raise ConfigurationError(msg)
    return value


def _read_hash_key(path: pathlib.Path) -> DeploymentKey:
    """Load the identifier hashing key from a file of raw bytes."""
    try:
        material = path.read_bytes()
    except OSError as error:
        msg = f"cannot read the hashing key at {path}: {error}"
        raise ConfigurationError(msg) from error
    try:
        return DeploymentKey(material)
    except ValueError as error:
        msg = f"the hashing key at {path} is not usable: {error}"
        raise ConfigurationError(msg) from error


def _read_ledger_key(path: pathlib.Path) -> Ed25519PrivateKey:
    """Load the checkpoint signing key from an unencrypted PEM file."""
    try:
        loaded = load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as error:
        msg = f"cannot read the signing key at {path}: {error}"
        raise ConfigurationError(msg) from error
    if not isinstance(loaded, Ed25519PrivateKey):
        msg = f"the signing key at {path} is not an Ed25519 key"
        raise ConfigurationError(msg)
    return loaded


def from_environment() -> Settings:
    """Build the settings from the environment, refusing to invent anything.

    Returns:
        The settings for this deployment.

    Raises:
        ConfigurationError: If a value with no safe default is absent, or a key
            file is present but unusable. A misconfigured key is a hard failure
            rather than a degraded mode: the operator meant to supply one, and
            running on without it would hide that they had not.
    """
    hash_key_file = os.environ.get(HASH_KEY_FILE, "").strip()
    ledger_key_file = os.environ.get(LEDGER_KEY_FILE, "").strip()
    limit = os.environ.get(MAX_UPLOAD_BYTES, "").strip()

    return Settings(
        database_url=_required(DATABASE_URL),
        checkpoint_id=_required(CHECKPOINT_ID),
        hash_key=_read_hash_key(pathlib.Path(hash_key_file)) if hash_key_file else None,
        ledger_key=_read_ledger_key(pathlib.Path(ledger_key_file)) if ledger_key_file else None,
        max_upload_bytes=int(limit) if limit else DEFAULT_MAX_UPLOAD_BYTES,
    )
