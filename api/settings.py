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
import datetime
import json
import os
import pathlib
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from api.trust import TrustConfigurationError, read_trust_anchors
from core.privacy.hashing import DeploymentKey
from core.privacy.retention import ArtefactCategory, RetentionPolicy
from detectors.rung0_crypto.trust_store import TrustStore

DATABASE_URL: Final[str] = "SENTINELID_DB_URL"
CHECKPOINT_ID: Final[str] = "SENTINELID_CHECKPOINT_ID"
HASH_KEY_FILE: Final[str] = "SENTINELID_HASH_KEY_FILE"
LEDGER_KEY_FILE: Final[str] = "SENTINELID_LEDGER_KEY_FILE"
MAX_UPLOAD_BYTES: Final[str] = "SENTINELID_MAX_UPLOAD_BYTES"
RETENTION_POLICY_FILE: Final[str] = "SENTINELID_RETENTION_POLICY_FILE"
TRUST_ANCHORS_FILE: Final[str] = "SENTINELID_TRUST_ANCHORS_FILE"

DEFAULT_MAX_UPLOAD_BYTES: Final[int] = 15 * 1024 * 1024
"""A cap on one capture. A policy limit, not a measurement of anything."""

NO_LEDGER_KEY: Final[str] = (
    "This checkpoint holds no signing key, so no ledger checkpoint can be published "
    "and no third party can yet verify these records."
)
NO_TRUST_ANCHORS: Final[str] = (
    "This checkpoint holds no issuer keys, so no document can be confirmed "
    "genuine here. Every document will need a person to decide."
)
"""The most consequential absence in the system, said on every case.

Rung 0 is the only rung that can clear a document. With no anchors it can never
answer, so every crossing reaches at best MANUAL_REVIEW. That is correct and
fail-closed, and it is also the difference between a screening system and a
queue, so it is not something to leave implicit.
"""

NO_RETENTION_POLICY: Final[str] = (
    "This checkpoint has no retention policy, so nothing stored here is ever "
    "destroyed. Records are being kept indefinitely."
)
"""Said out loud, because an unenforced retention policy is invisible otherwise.

Rules 3 and 4 of CLAUDE.md put limits on how long identifiers and biometrics may
be held. A deployment with no policy file keeps everything forever, and there is
nothing on screen to reveal it. That is silence about a check that did not
happen, which CLAUDE.md calls a defect.
"""

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

    trust_store: TrustStore = dataclasses.field(default_factory=TrustStore)
    """The issuer keys this checkpoint will rely on.

    Empty by default, and empty is a legitimate state: it means nothing can be
    cleared cryptographically. It is never populated by discovery — an anchor is
    a file an operator put there deliberately.
    """

    retention_policy: RetentionPolicy | None = None
    """How long each kind of stored artefact may be kept.

    Optional here, and absent by default, because there is no safe default
    window and inventing one would put an invented day count into production as
    policy. A deployment without one can still screen documents; it simply never
    destroys anything, and :meth:`unavailable` says so.
    """

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
        if len(self.trust_store) == 0:
            missing.append(NO_TRUST_ANCHORS)
        if self.retention_policy is None:
            missing.append(NO_RETENTION_POLICY)
        return tuple(missing)


def _read_anchors(path: pathlib.Path) -> TrustStore:
    """Read trust anchors, reporting a bad file the way every other setting does.

    Wrapped so that a caller catching `ConfigurationError` at start-up catches
    this too. A deployment that failed to start for one reason and crashed for
    another would be a worse thing to debug at a checkpoint.
    """
    try:
        return read_trust_anchors(path)
    except TrustConfigurationError as error:
        raise ConfigurationError(str(error)) from error


def _required(name: str) -> str:
    """Read an environment variable that has no safe default."""
    value = os.environ.get(name, "").strip()
    if not value:
        msg = f"{name} is not set, and there is no safe default for it"
        raise ConfigurationError(msg)
    return value


def read_retention_policy(path: pathlib.Path) -> RetentionPolicy:
    """Read a retention policy from a JSON file of whole days per category.

    The file names every category explicitly. `RetentionPolicy` refuses to
    construct if one is missing, which is the point: the deployment does not
    start destroying things until somebody has answered every question.

    Args:
        path: The policy file. A JSON object mapping each `ArtefactCategory`
            name to a positive number of days. A UTF-8 byte order mark is
            accepted, because Windows tooling writes one.

    Returns:
        The policy.

    Raises:
        ConfigurationError: If the file cannot be read, is not the expected
            shape, or leaves a category unanswered. Refused rather than
            defaulted, for the same reason the windows have no defaults.
    """
    try:
        # utf-8-sig, not utf-8: PowerShell writes a byte order mark by default on
        # Windows, and refusing an operator's policy file over an invisible
        # character is a trap. Without a mark it is identical to utf-8.
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as error:
        msg = f"cannot read the retention policy at {path}: {error}"
        raise ConfigurationError(msg) from error
    except json.JSONDecodeError as error:
        msg = f"the retention policy at {path} is not valid JSON: {error}"
        raise ConfigurationError(msg) from error

    if not isinstance(loaded, dict):
        msg = f"the retention policy at {path} must be a JSON object of category to days"
        raise ConfigurationError(msg)

    windows: dict[ArtefactCategory, datetime.timedelta] = {}
    for name, days in loaded.items():
        try:
            category = ArtefactCategory(name)
        except ValueError as error:
            msg = f"{name!r} in {path} is not a retention category"
            raise ConfigurationError(msg) from error
        if not isinstance(days, int | float) or isinstance(days, bool):
            msg = f"the window for {name} in {path} must be a number of days"
            raise ConfigurationError(msg)
        windows[category] = datetime.timedelta(days=days)

    try:
        return RetentionPolicy(windows=windows)
    except ValueError as error:
        msg = f"the retention policy at {path} is not usable: {error}"
        raise ConfigurationError(msg) from error


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
    retention_file = os.environ.get(RETENTION_POLICY_FILE, "").strip()
    anchors_file = os.environ.get(TRUST_ANCHORS_FILE, "").strip()
    ledger_key_file = os.environ.get(LEDGER_KEY_FILE, "").strip()
    limit = os.environ.get(MAX_UPLOAD_BYTES, "").strip()

    return Settings(
        database_url=_required(DATABASE_URL),
        checkpoint_id=_required(CHECKPOINT_ID),
        hash_key=_read_hash_key(pathlib.Path(hash_key_file)) if hash_key_file else None,
        ledger_key=_read_ledger_key(pathlib.Path(ledger_key_file)) if ledger_key_file else None,
        max_upload_bytes=int(limit) if limit else DEFAULT_MAX_UPLOAD_BYTES,
        trust_store=(_read_anchors(pathlib.Path(anchors_file)) if anchors_file else TrustStore()),
        retention_policy=(
            read_retention_policy(pathlib.Path(retention_file)) if retention_file else None
        ),
    )
