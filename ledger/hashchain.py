"""An append-only Merkle transparency log, with Ed25519 signed checkpoints.

The construction is the one RFC 6962 uses for certificate transparency, and the
detail that matters is the **domain separation**: a leaf is hashed with a `0x00`
prefix and an internal node with `0x01`. Without that, an attacker can present
an internal node as if it were a leaf and produce a valid-looking proof for
something that was never logged. It is one byte, and it is the difference
between a log and a decoration.

**What this gives you, and what it does not.** It gives tamper *evidence*: given
a checkpoint published outside the operator's control, anyone can show that an
entry was in the log at that time and has not changed since. It does not give
tamper *prevention* — an operator with the database can still delete it. ADR
0003 says exactly this, and it is worth repeating at the implementation.

Everything here is a pure function over bytes. No storage, no clock, no network.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

LEAF_PREFIX: Final[bytes] = b"\x00"
"""Distinguishes a leaf from an internal node. See the module docstring."""

NODE_PREFIX: Final[bytes] = b"\x01"
"""Distinguishes an internal node from a leaf."""

EMPTY_ROOT: Final[bytes] = hashlib.sha256(b"").digest()
"""The root of an empty log. Defined so an empty log still has a checkpoint."""


class LedgerError(ValueError):
    """A proof, checkpoint or index that cannot be reasoned about."""


def leaf_hash(payload: bytes) -> bytes:
    """Return the hash of one log entry.

    Args:
        payload: The entry's canonical bytes.

    Returns:
        The leaf hash, domain separated from internal nodes.
    """
    return hashlib.sha256(LEAF_PREFIX + payload).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Return the hash of an internal node.

    Args:
        left: The left child's hash.
        right: The right child's hash.

    Returns:
        The node hash, domain separated from leaves.
    """
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """Return the Merkle root over an ordered list of leaf hashes.

    Args:
        leaves: The leaf hashes, in the order they were appended.

    Returns:
        The root. An empty log has a defined root rather than an error, so a
        checkpoint can be published before anything has been logged.
    """
    if not leaves:
        return EMPTY_ROOT

    level = list(leaves)
    while len(level) > 1:
        pairs = zip(level[0::2], level[1::2], strict=False)
        nodes = [node_hash(left, right) for left, right in pairs]
        if len(level) % 2:
            # An odd node is carried up unchanged rather than paired with
            # itself. Duplicating it would make two different logs share a root.
            nodes.append(level[-1])
        level = nodes
    return level[0]


def inclusion_proof(leaves: list[bytes], index: int) -> tuple[bytes, ...]:
    """Return the sibling hashes proving one leaf is in the log.

    Args:
        leaves: Every leaf hash, in order.
        index: Which leaf to prove.

    Returns:
        The sibling hashes, from the leaf upward.

    Raises:
        LedgerError: If the index is not in the log.
    """
    if not 0 <= index < len(leaves):
        msg = f"no entry at index {index} in a log of {len(leaves)}"
        raise LedgerError(msg)

    proof: list[bytes] = []
    level = list(leaves)
    position = index
    while len(level) > 1:
        nodes: list[bytes] = []
        for start in range(0, len(level) - 1, 2):
            nodes.append(node_hash(level[start], level[start + 1]))
        carried = len(level) % 2 == 1
        if carried:
            nodes.append(level[-1])

        if carried and position == len(level) - 1:
            pass  # Carried up unchanged; it has no sibling at this level.
        elif position % 2:
            proof.append(level[position - 1])
        else:
            proof.append(level[position + 1])

        position //= 2
        level = nodes
    return tuple(proof)


def verify_inclusion(
    leaf: bytes, *, index: int, size: int, proof: tuple[bytes, ...], root: bytes
) -> bool:
    """Report whether a leaf is provably in a log with a given root.

    This is the function a third party runs. It needs the leaf, its position,
    the log size, the proof and a published root — and nothing from the system
    that produced them, which is the point.

    Args:
        leaf: The leaf hash being proved.
        index: Its position in the log.
        size: How many entries the log held at the checkpoint.
        proof: The sibling hashes.
        root: The published root.

    Returns:
        Whether the proof holds.
    """
    if not 0 <= index < size:
        return False

    computed = leaf
    position, remaining, offered = index, size, list(proof)
    while remaining > 1:
        carried = remaining % 2 == 1
        if carried and position == remaining - 1:
            position //= 2
            remaining = remaining // 2 + 1
            continue
        if not offered:
            return False
        sibling = offered.pop(0)
        computed = node_hash(sibling, computed) if position % 2 else node_hash(computed, sibling)
        position //= 2
        remaining = remaining // 2 + (1 if carried else 0)
    return not offered and computed == root


@dataclass(frozen=True)
class Checkpoint:
    """A signed statement that the log had a given root at a given size.

    This is what gets published outside the operator's control. Without that
    publication the log proves nothing, because whoever holds the database can
    recompute the whole chain. ADR 0003 is explicit about it.
    """

    tree_size: int
    root: bytes
    signed_at: datetime.datetime
    signature: bytes

    def signed_bytes(self) -> bytes:
        """Return the bytes the signature covers."""
        return signed_checkpoint_bytes(self.tree_size, self.root, self.signed_at)


def signed_checkpoint_bytes(tree_size: int, root: bytes, signed_at: datetime.datetime) -> bytes:
    """Return the canonical bytes a checkpoint signature covers.

    Args:
        tree_size: How many entries the log holds.
        root: The Merkle root.
        signed_at: When the checkpoint was made. Must carry a timezone.

    Returns:
        The bytes to sign or verify.

    Raises:
        LedgerError: If the timestamp is naive, which would make two
            checkpoints from different zones look identical.
    """
    if signed_at.tzinfo is None or signed_at.tzinfo.utcoffset(signed_at) is None:
        msg = "a checkpoint timestamp must be timezone aware"
        raise LedgerError(msg)
    return b"sentinelid-checkpoint-v1|%d|%s|%s" % (
        tree_size,
        root.hex().encode(),
        signed_at.isoformat().encode(),
    )


def sign_checkpoint(
    *,
    tree_size: int,
    root: bytes,
    signed_at: datetime.datetime,
    key: Ed25519PrivateKey,
) -> Checkpoint:
    """Sign a statement about the log's current state.

    Args:
        tree_size: How many entries the log holds.
        root: The Merkle root over those entries.
        signed_at: When the checkpoint is being made.
        key: The log's signing key.

    Returns:
        The signed checkpoint.
    """
    payload = signed_checkpoint_bytes(tree_size, root, signed_at)
    return Checkpoint(
        tree_size=tree_size, root=root, signed_at=signed_at, signature=key.sign(payload)
    )


def verify_checkpoint(checkpoint: Checkpoint, *, key: Ed25519PublicKey) -> bool:
    """Report whether a checkpoint was signed by the log's key.

    Args:
        checkpoint: The checkpoint to verify.
        key: The log's public key.

    Returns:
        Whether the signature holds. False rather than an exception, because a
        forged checkpoint is a result to report, not a crash.
    """
    try:
        key.verify(checkpoint.signature, checkpoint.signed_bytes())
    except (InvalidSignature, LedgerError):
        return False
    return True
