"""Consistency proofs: the log was appended to, not rewritten.

An inclusion proof says one entry is in the log. It says nothing about whether
the log used to say something else. An operator holding the database can
recompute a whole different history in which every individual inclusion proof
still verifies. A consistency proof is what closes that: it ties an earlier
published checkpoint to a later one and shows the earlier is a prefix of the
later, unchanged.

**Two things are property-tested rather than sampled**, because this is the
kind of code that is right on the cases an author thinks of and wrong on the
one an attacker finds:

- the project's tree really is the RFC 6962 tree, which is what makes it valid
  to implement the standard algorithm rather than invent one;
- for every pair of sizes, a genuine proof verifies, and any change to the
  entries the earlier checkpoint covered makes it fail.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ledger.hashchain import (
    EMPTY_ROOT,
    LedgerError,
    consistency_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_consistency,
)

MAX_LEAVES = 65
"""Enough to cross several power-of-two boundaries, which is where this breaks."""


def leaves(count: int, *, salt: bytes = b"") -> list[bytes]:
    """Return `count` distinct leaf hashes, reproducibly."""
    return [leaf_hash(salt + index.to_bytes(4, "big")) for index in range(count)]


def rfc6962_root(items: list[bytes]) -> bytes:
    """The Merkle Tree Hash of RFC 6962 section 2.1, written from the standard.

    Deliberately recursive and deliberately not the project's implementation.
    Agreeing with this is what licenses the use of the standard's consistency
    proof algorithm against the project's level-by-level tree.
    """
    if not items:
        return EMPTY_ROOT
    if len(items) == 1:
        return items[0]
    split = 1
    while split * 2 < len(items):
        split *= 2
    return node_hash(rfc6962_root(items[:split]), rfc6962_root(items[split:]))


# The tree is the standard's tree


@pytest.mark.parametrize("count", range(MAX_LEAVES))
def test_the_project_tree_is_the_rfc6962_tree(count: int) -> None:
    """If this ever fails, the consistency algorithm below is no longer justified."""
    items = leaves(count)

    assert merkle_root(items) == rfc6962_root(items)


# A genuine proof verifies


@given(
    old_size=st.integers(min_value=0, max_value=40),
    growth=st.integers(min_value=0, max_value=40),
)
def test_a_genuine_extension_verifies(old_size: int, growth: int) -> None:
    """For every pair of sizes, appending entries keeps the log consistent."""
    new_size = old_size + growth
    items = leaves(new_size)
    old_root = merkle_root(items[:old_size])

    assert verify_consistency(
        old_size=old_size,
        new_size=new_size,
        old_root=old_root,
        new_root=merkle_root(items),
        proof=consistency_proof(items, old_size),
    )


@pytest.mark.parametrize("old_size", range(1, 33))
def test_an_unchanged_log_is_consistent_with_itself(old_size: int) -> None:
    """A log that has not grown is still a log that was not rewritten."""
    items = leaves(old_size)
    root = merkle_root(items)

    assert consistency_proof(items, old_size) == ()
    assert verify_consistency(
        old_size=old_size, new_size=old_size, old_root=root, new_root=root, proof=()
    )


def test_every_log_extends_the_empty_log() -> None:
    """There is nothing to prove, and the empty root still has to be the empty one."""
    items = leaves(9)

    assert consistency_proof(items, 0) == ()
    assert verify_consistency(
        old_size=0, new_size=9, old_root=EMPTY_ROOT, new_root=merkle_root(items), proof=()
    )


# A rewritten history does not


@given(
    old_size=st.integers(min_value=1, max_value=24),
    growth=st.integers(min_value=1, max_value=24),
    data=st.data(),
)
def test_changing_a_covered_entry_breaks_the_proof(
    old_size: int, growth: int, data: st.DataObject
) -> None:
    """The property that matters: the past cannot be edited and still verify.

    One entry inside the range the earlier checkpoint covered is replaced. The
    later log then is not an extension of the earlier one, and no proof over it
    may verify against the earlier root.
    """
    new_size = old_size + growth
    honest = leaves(new_size)
    old_root = merkle_root(honest[:old_size])

    index = data.draw(st.integers(min_value=0, max_value=old_size - 1))
    rewritten = list(honest)
    rewritten[index] = leaf_hash(b"rewritten" + index.to_bytes(4, "big"))

    assert not verify_consistency(
        old_size=old_size,
        new_size=new_size,
        old_root=old_root,
        new_root=merkle_root(rewritten),
        proof=consistency_proof(rewritten, old_size),
    )


@given(
    old_size=st.integers(min_value=1, max_value=24),
    growth=st.integers(min_value=1, max_value=24),
)
def test_dropping_an_entry_breaks_the_proof(old_size: int, growth: int) -> None:
    """Removing an entry and appending others must not pass as an extension."""
    new_size = old_size + growth
    honest = leaves(new_size)
    old_root = merkle_root(honest[:old_size])

    truncated = honest[1:]

    assert not verify_consistency(
        old_size=old_size,
        new_size=len(truncated),
        old_root=old_root,
        new_root=merkle_root(truncated),
        proof=consistency_proof(truncated, old_size),
    )


@given(
    old_size=st.integers(min_value=1, max_value=20),
    growth=st.integers(min_value=1, max_value=20),
)
def test_a_proof_from_a_different_log_does_not_verify(old_size: int, growth: int) -> None:
    """A proof is about one log. One built elsewhere must not be reusable."""
    new_size = old_size + growth
    honest = leaves(new_size)
    other = leaves(new_size, salt=b"other")

    assert not verify_consistency(
        old_size=old_size,
        new_size=new_size,
        old_root=merkle_root(honest[:old_size]),
        new_root=merkle_root(honest),
        proof=consistency_proof(other, old_size),
    )


# Refusals


def test_a_proof_larger_than_the_log_is_refused() -> None:
    """A claim about more entries than exist is not a question this can answer."""
    with pytest.raises(LedgerError, match="cannot prove consistency"):
        consistency_proof(leaves(4), 9)


def test_a_negative_size_is_refused() -> None:
    """There is no log of minus one entries."""
    with pytest.raises(LedgerError, match="cannot have held"):
        consistency_proof(leaves(4), -1)


def test_a_shrinking_log_never_verifies() -> None:
    """The obvious lie, checked explicitly rather than left to the properties."""
    items = leaves(9)

    assert not verify_consistency(
        old_size=9,
        new_size=4,
        old_root=merkle_root(items),
        new_root=merkle_root(items[:4]),
        proof=(),
    )


def test_an_empty_proof_for_a_grown_log_does_not_verify() -> None:
    """Growth without evidence is a claim, not a proof."""
    items = leaves(9)

    assert not verify_consistency(
        old_size=4,
        new_size=9,
        old_root=merkle_root(items[:4]),
        new_root=merkle_root(items),
        proof=(),
    )


def test_a_truncated_proof_does_not_verify() -> None:
    """Dropping a node from a genuine proof must fail rather than skip a step."""
    items = leaves(21)
    proof = consistency_proof(items, 9)

    assert not verify_consistency(
        old_size=9,
        new_size=21,
        old_root=merkle_root(items[:9]),
        new_root=merkle_root(items),
        proof=proof[:-1],
    )


def test_an_extended_proof_does_not_verify() -> None:
    """Nor may a proof carry a node the verifier did not consume."""
    items = leaves(21)
    proof = consistency_proof(items, 9)

    assert not verify_consistency(
        old_size=9,
        new_size=21,
        old_root=merkle_root(items[:9]),
        new_root=merkle_root(items),
        proof=(*proof, leaf_hash(b"extra")),
    )


def test_the_empty_log_claim_must_use_the_empty_root() -> None:
    """Claiming an empty earlier log with some other root proves nothing."""
    items = leaves(9)

    assert not verify_consistency(
        old_size=0,
        new_size=9,
        old_root=leaf_hash(b"invented"),
        new_root=merkle_root(items),
        proof=(),
    )
