#!/usr/bin/env python3
"""Verify a SENTINEL ID checkpoint. Standalone: run this without the system.

    python verify_checkpoint.py CHECKPOINT.json
    python verify_checkpoint.py first.json second.json ...

You need Python 3 and the `cryptography` package. Nothing else — in particular,
you do **not** need SENTINEL ID, its database, or anything else the operator
controls. That is the entire point. A verifier supplied and run by the operator
proves nothing about the operator.

This file deliberately re-implements the checkpoint byte layout rather than
importing it. An independent implementation is what makes verification worth
doing; a check that shares code with the thing it checks agrees with it by
construction. The system's own test suite pins the two against each other, so
they cannot drift apart silently.

WHAT A PASSING CHECK MEANS
    The named checkpoint signed a statement that its log held exactly this many
    entries, with this Merkle root, at this time. The signature is intact.

WHAT IT DOES NOT MEAN
    It says nothing about whether the entries are true, whether any decision was
    correct, or what any of them said.

CONSISTENCY
    A checkpoint published with --since carries a cryptographic proof that it
    extends an earlier one: that every entry the earlier checkpoint covered is
    still there, unchanged, in the same order. Pass several checkpoints to this
    script and it checks those proofs. That is the difference between "the log
    grew" and "the log was only appended to" - without it, whoever holds the
    database can publish an entirely different history in which every single
    entry still proves its own inclusion.

    A checkpoint published without --since carries no such proof. This script
    then falls back to comparing sizes, says so, and calls the result weaker
    than a proof, because it is.

KEEP EVERY CHECKPOINT YOU ARE SENT. A single one, held only by the operator,
is worth very little. A series, held by somebody else, is the evidence.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import pathlib
import sys

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()
"""RFC 6962 domain separation, rebuilt here rather than imported."""


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash an internal Merkle node."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """Check that a log of new_size provably extends one of old_size.

    RFC 6962 section 2.1.4, written out here so that this file depends on
    nothing from the system it is checking.

    Args:
        old_size: Entries in the earlier checkpoint.
        new_size: Entries in the later checkpoint.
        old_root: The earlier checkpoint's Merkle root.
        new_root: The later checkpoint's Merkle root.
        proof: The proof nodes carried by the later checkpoint.

    Returns:
        Whether the earlier log is an unchanged prefix of the later one.
    """
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof and old_root == EMPTY_ROOT

    node, last = old_size - 1, new_size - 1
    while node % 2:
        node //= 2
        last //= 2

    offered = list(proof)
    if not offered:
        return False

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


EXPECTED_FORMAT = "sentinelid-checkpoint-v1"
"""The only byte layout this script knows how to check."""

REQUIRED = ("format", "checkpoint_id", "tree_size", "root", "signed_at", "signature", "public_key")
"""Every field a verifier needs. A file missing one cannot be checked at all."""


def signed_bytes(tree_size: int, root_hex: str, signed_at: str) -> bytes:
    """Rebuild the exact bytes the signature covers.

    Independent of the system that produced them, on purpose.

    Args:
        tree_size: How many entries the log claimed to hold.
        root_hex: The Merkle root, hex encoded.
        signed_at: The ISO-8601 timestamp, exactly as written in the file.

    Returns:
        The signed payload.
    """
    return b"sentinelid-checkpoint-v1|%d|%s|%s" % (
        tree_size,
        root_hex.encode(),
        signed_at.encode(),
    )


def load(path: pathlib.Path) -> dict[str, object]:
    """Read one checkpoint file and reject anything malformed."""
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict):
        msg = f"{path} does not contain a checkpoint"
        raise ValueError(msg)
    missing = [field for field in REQUIRED if field not in document]
    if missing:
        msg = f"{path} is missing {', '.join(missing)}"
        raise ValueError(msg)
    if document["format"] != EXPECTED_FORMAT:
        msg = f"{path} is format {document['format']!r}, and this script checks {EXPECTED_FORMAT!r}"
        raise ValueError(msg)
    return document


def verify(document: dict[str, object]) -> bool:
    """Report whether a checkpoint's signature is intact.

    Args:
        document: A loaded checkpoint file.

    Returns:
        Whether the signature verifies under the public key in the file.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(document["public_key"])))
    payload = signed_bytes(
        int(document["tree_size"]),  # type: ignore[arg-type]
        str(document["root"]),
        str(document["signed_at"]),
    )
    try:
        key.verify(bytes.fromhex(str(document["signature"])), payload)
    except InvalidSignature:
        return False
    return True


def report_series(documents: list[dict[str, object]]) -> int:
    """Check a series of checkpoints for the one property a series can show.

    Args:
        documents: Verified checkpoints, in the order given.

    Returns:
        How many problems were found.
    """
    ordered = sorted(documents, key=lambda item: str(item["signed_at"]))
    problems = 0

    identities = {str(item["checkpoint_id"]) for item in ordered}
    if len(identities) > 1:
        print(f"\nNOTE: these checkpoints come from {len(identities)} different checkpoints:")
        for identity in sorted(identities):
            print(f"  {identity}")
        print("  Compare each one's series separately; they are different logs.")
        return problems

    keys = {str(item["public_key"]) for item in ordered}
    if len(keys) > 1:
        print("\nPROBLEM: the signing key changed between these checkpoints.")
        print("  That may be a legitimate key rotation, and it may not.")
        print("  Ask the operator when the key was rotated and why, and do not")
        print("  treat checkpoints under the new key as continuing the old series.")
        problems += 1

    print("\nSeries, oldest first:")
    previous: dict[str, object] | None = None
    for item in ordered:
        size = int(item["tree_size"])
        line = f"  {item['signed_at']}  {size:>8} entries  {item['root']}"
        if previous is not None:
            outcome, failed = _link(previous, item)
            line += f"   {outcome}"
            problems += failed
        print(line)
        previous = item

    if problems:
        print("\nThis log was not simply appended to. Ask for an explanation, and")
        print("keep these files: they are the evidence that something changed.")
    else:
        print("\nEvery link above was checked.")
    return problems


def _link(previous: dict[str, object], item: dict[str, object]) -> tuple[str, int]:
    """Describe how one checkpoint relates to the one before it.

    Returns:
        A short verdict for the table, and 1 if it is a problem.
    """
    old_size = int(previous["tree_size"])
    new_size = int(item["tree_size"])

    if new_size < old_size:
        return "<-- SHRANK: entries were removed", 1

    carried = item.get("consistency")
    if isinstance(carried, dict) and int(carried.get("from_size", -1)) == old_size:
        if str(carried.get("from_root")) != str(previous["root"]):
            return "<-- proof is about a different earlier log", 1
        proved = verify_consistency(
            old_size,
            new_size,
            bytes.fromhex(str(previous["root"])),
            bytes.fromhex(str(item["root"])),
            [bytes.fromhex(str(node)) for node in carried.get("proof", [])],
        )
        if proved:
            return "PROVED to extend the previous checkpoint", 0
        return "<-- CONSISTENCY PROOF FAILED: the past was rewritten", 1

    if new_size == old_size and str(item["root"]) != str(previous["root"]):
        return "<-- SAME SIZE, DIFFERENT ROOT: history was rewritten", 1
    return "grew, but carries no proof (published without --since)", 0


def main(argv: list[str]) -> int:
    """Verify every checkpoint named on the command line."""
    if not argv:
        print(__doc__)
        return 2

    verified: list[dict[str, object]] = []
    failures = 0

    for name in argv:
        path = pathlib.Path(name)
        try:
            document = load(path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"FAIL  {path}: {error}")
            failures += 1
            continue

        if verify(document):
            when = str(document["signed_at"])
            with contextlib.suppress(ValueError):
                when = datetime.datetime.fromisoformat(when).strftime("%Y-%m-%d %H:%M:%S %Z")
            print(
                f"OK    {path}\n"
                f"      checkpoint {document['checkpoint_id']}, "
                f"{document['tree_size']} entries, signed {when}"
            )
            verified.append(document)
        else:
            print(f"FAIL  {path}: the signature does not match this checkpoint's contents.")
            failures += 1

    if len(verified) > 1:
        failures += report_series(verified)

    if failures:
        print(f"\n{failures} problem(s). Do not treat this log as trustworthy without an answer.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
