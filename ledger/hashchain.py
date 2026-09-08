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


def _largest_power_of_two_below(size: int) -> int:
    """Return the largest power of two strictly less than `size`.

    Args:
        size: A count greater than one.

    Returns:
        The split point RFC 6962 uses to divide a tree.
    """
    split = 1
    while split * 2 < size:
        split *= 2
    return split


def _subproof(old_size: int, leaves: list[bytes], *, complete: bool) -> list[bytes]:
    """Return the RFC 6962 SUBPROOF for an old log inside a longer one.

    Args:
        old_size: How many leaves the old log held.
        leaves: The subtree being descended, oldest first.
        complete: Whether `old_size` covers this whole subtree, in which case
            its root is already known to the verifier and is not sent.

    Returns:
        The proof nodes for this subtree, in verification order.
    """
    if old_size == len(leaves):
        return [] if complete else [merkle_root(leaves)]

    split = _largest_power_of_two_below(len(leaves))
    if old_size <= split:
        return [
            *_subproof(old_size, leaves[:split], complete=complete),
            merkle_root(leaves[split:]),
        ]
    return [
        *_subproof(old_size - split, leaves[split:], complete=False),
        merkle_root(leaves[:split]),
    ]


def consistency_proof(leaves: list[bytes], old_size: int) -> tuple[bytes, ...]:
    """Return a proof that a shorter log is a prefix of this one.

    This is what turns "the log grew" into "the log was only appended to". An
    inclusion proof says one entry is present; a consistency proof says that
    everything the log said earlier it still says, and that nothing was removed
    or rewritten in between. Without it, an operator holding the database can
    republish a different history and every individual proof still checks out.

    Args:
        leaves: Every leaf hash in the current log, in order.
        old_size: How many entries the earlier checkpoint claimed.

    Returns:
        The proof nodes. Empty when the log has not changed, which is a valid
        proof rather than a missing one.

    Raises:
        LedgerError: If `old_size` is negative or larger than the log, which
            would be a claim about a log this one cannot be an extension of.
    """
    if old_size < 0:
        msg = f"a log cannot have held {old_size} entries"
        raise LedgerError(msg)
    if old_size > len(leaves):
        msg = f"cannot prove consistency with {old_size} entries from a log of {len(leaves)}"
        raise LedgerError(msg)
    if old_size == 0 or old_size == len(leaves):
        return ()
    return tuple(_subproof(old_size, list(leaves), complete=True))


def verify_consistency(
    *,
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: tuple[bytes, ...],
) -> bool:
    """Report whether a log of `new_size` provably extends one of `old_size`.

    This is the check a third party runs against two checkpoints it was given
    at different times. It needs no leaves and nothing from the operator.

    Args:
        old_size: Entry count in the earlier checkpoint.
        new_size: Entry count in the later checkpoint.
        old_root: Merkle root the earlier checkpoint committed to.
        new_root: Merkle root the later checkpoint committed to.
        proof: The nodes from :func:`consistency_proof`.

    Returns:
        Whether the later log contains the earlier one unchanged, as a prefix.
    """
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        # Every log extends the empty log, and there is nothing to prove. The
        # earlier root still has to be the empty one, or the claim is not about
        # an empty log at all.
        return not proof and old_root == EMPTY_ROOT

    node, last = old_size - 1, new_size - 1
    while node % 2:
        node //= 2
        last //= 2

    offered = list(proof)
    if not offered:
        return False

    # When `node` has reached zero the old log was a complete subtree, so its
    # root is already known to the verifier and is not repeated in the proof.
    computed_old = offered.pop(0) if node else old_root
    computed_new = computed_old

    while node:
        if node % 2:
            if not offered:
                return False
            sibling = offered.pop(0)
            computed_old = node_hash(sibling, computed_old)
            computed_new = node_hash(sibling, computed_new)
        elif node < last:
            if not offered:
                return False
            computed_new = node_hash(computed_new, offered.pop(0))
        node //= 2
        last //= 2

    while last:
        if not offered:
            return False
        computed_new = node_hash(computed_new, offered.pop(0))
        last //= 2

    return not offered and computed_old == old_root and computed_new == new_root


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
