"""The transparency log, and the two things it must never get wrong.

A Merkle log that verifies its own proofs is easy. The failures that matter are
the ones where it verifies something it should refuse: a proof under the wrong
root, an internal node presented as a leaf, or two different logs agreeing on a
root. Most of this file is about those.

The second half is about replay. The log stores a digest of a verdict, so the
claim "this decision can be replayed and checked against the log" holds only if
re-running a case produces the same bytes. Two tests pin exactly which
differences are allowed to survive that comparison and which are not.
"""

from __future__ import annotations

import dataclasses
import datetime
from typing import Final

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from core.contracts import Result, Rung
from core.trust.ladder import resolve
from ledger.hashchain import (
    EMPTY_ROOT,
    Checkpoint,
    LedgerError,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    sign_checkpoint,
    verify_checkpoint,
    verify_inclusion,
)
from ledger.interface import LedgerEntry, TransparencyLog, append_entry, canonical_verdict_bytes
from tests.support import DECIDED_AT, evidence, provenance

SIGNED_AT: Final[datetime.datetime] = datetime.datetime(2026, 9, 7, 12, 0, tzinfo=datetime.UTC)
"""A fixed instant, so checkpoint bytes in these tests are reproducible."""


def leaves(count: int) -> list[bytes]:
    """Return a log of a given size, each entry distinct."""
    return [leaf_hash(f"entry-{index}".encode()) for index in range(count)]


def test_an_empty_log_still_has_a_root() -> None:
    """A checkpoint can be published before anything has been logged."""
    assert merkle_root([]) == EMPTY_ROOT


def test_a_leaf_and_an_internal_node_are_hashed_differently() -> None:
    """The one byte that stops an internal node being presented as a leaf.

    Without the domain separation prefixes, `leaf_hash(left + right)` and
    `node_hash(left, right)` would be the same value, and an attacker could
    offer an internal node as proof that something was logged which never was.
    """
    left, right = leaf_hash(b"left"), leaf_hash(b"right")

    assert leaf_hash(left + right) != node_hash(left, right)


def test_appending_changes_the_root() -> None:
    """A log whose root survived an append would record nothing."""
    assert merkle_root(leaves(4)) != merkle_root(leaves(5))


def test_two_different_logs_never_share_a_root() -> None:
    """An odd leaf is carried up, not duplicated.

    The usual shortcut for an odd node is to pair it with itself, which makes a
    log of three entries hash identically to a log of four whose last entry is
    repeated. Someone could then claim an entry was logged twice, or hide that
    it was not.
    """
    three = leaves(3)
    four_with_a_repeat = [*three, three[-1]]

    assert merkle_root(three) != merkle_root(four_with_a_repeat)


@pytest.mark.parametrize("size", range(1, 18))
def test_every_entry_in_a_log_can_be_proved(size: int) -> None:
    """Inclusion holds at every index, at every size, including the odd ones."""
    log = leaves(size)
    root = merkle_root(log)

    for index in range(size):
        proof = inclusion_proof(log, index)
        assert verify_inclusion(log[index], index=index, size=size, proof=proof, root=root), (
            f"index {index} of {size}"
        )


def test_a_proof_fails_under_a_foreign_root() -> None:
    """The root is what a third party trusts, so it has to be the thing checked."""
    log = leaves(6)
    proof = inclusion_proof(log, 2)

    assert not verify_inclusion(log[2], index=2, size=6, proof=proof, root=merkle_root(leaves(7)))


def test_a_proof_does_not_transfer_to_another_leaf() -> None:
    """A valid proof for one entry must not prove a different one."""
    log = leaves(6)
    proof = inclusion_proof(log, 2)

    assert not verify_inclusion(log[3], index=2, size=6, proof=proof, root=merkle_root(log))


def test_a_padded_proof_is_rejected() -> None:
    """Leftover siblings mean the verifier and the log disagree about the shape."""
    log = leaves(6)
    proof = (*inclusion_proof(log, 2), leaf_hash(b"extra"))

    assert not verify_inclusion(log[2], index=2, size=6, proof=proof, root=merkle_root(log))


def test_a_truncated_proof_is_rejected() -> None:
    """A short proof must fail rather than stop early and declare success."""
    log = leaves(6)
    proof = inclusion_proof(log, 2)[:-1]

    assert not verify_inclusion(log[2], index=2, size=6, proof=proof, root=merkle_root(log))


@pytest.mark.parametrize("index", [-1, 5, 99])
def test_an_index_outside_the_log_cannot_be_proved(index: int) -> None:
    """Asking for a proof of something absent is an error, not an empty proof."""
    with pytest.raises(LedgerError):
        inclusion_proof(leaves(5), index)


@pytest.mark.parametrize(("index", "size"), [(-1, 4), (4, 4), (0, 0)])
def test_verification_refuses_an_impossible_position(index: int, size: int) -> None:
    """The verifier reports False rather than raising: a bad proof is a result."""
    assert not verify_inclusion(leaf_hash(b"x"), index=index, size=size, proof=(), root=EMPTY_ROOT)


@given(st.integers(min_value=1, max_value=64), st.data())
def test_inclusion_holds_at_any_size(size: int, data: st.DataObject) -> None:
    """The proof arithmetic holds for sizes this file does not enumerate."""
    index = data.draw(st.integers(min_value=0, max_value=size - 1))
    log = leaves(size)

    assert verify_inclusion(
        log[index],
        index=index,
        size=size,
        proof=inclusion_proof(log, index),
        root=merkle_root(log),
    )


def test_a_checkpoint_verifies_under_its_own_key() -> None:
    """The published statement is what makes the log worth anything."""
    key = Ed25519PrivateKey.generate()
    checkpoint = sign_checkpoint(
        tree_size=3, root=merkle_root(leaves(3)), signed_at=SIGNED_AT, key=key
    )

    assert verify_checkpoint(checkpoint, key=key.public_key())


def test_a_checkpoint_from_another_key_is_rejected() -> None:
    """Anyone can compute a root; only the log can sign one."""
    checkpoint = sign_checkpoint(
        tree_size=3,
        root=merkle_root(leaves(3)),
        signed_at=SIGNED_AT,
        key=Ed25519PrivateKey.generate(),
    )

    assert not verify_checkpoint(checkpoint, key=Ed25519PrivateKey.generate().public_key())


def test_an_altered_checkpoint_is_rejected() -> None:
    """Changing the root after signing is the attack the signature exists for."""
    key = Ed25519PrivateKey.generate()
    checkpoint = sign_checkpoint(
        tree_size=3, root=merkle_root(leaves(3)), signed_at=SIGNED_AT, key=key
    )
    altered = dataclasses.replace(checkpoint, root=merkle_root(leaves(4)))

    assert not verify_checkpoint(altered, key=key.public_key())


def test_a_checkpoint_cannot_be_signed_without_a_timezone() -> None:
    """Two checkpoints from different zones would otherwise sign identical bytes."""
    with pytest.raises(LedgerError):
        sign_checkpoint(
            tree_size=0,
            root=EMPTY_ROOT,
            signed_at=datetime.datetime(2026, 9, 7, 12, 0),  # Naive on purpose.
            key=Ed25519PrivateKey.generate(),
        )


def test_a_naive_checkpoint_fails_verification_rather_than_crashing() -> None:
    """A malformed checkpoint arriving from outside is a result to report."""
    checkpoint = Checkpoint(
        tree_size=0,
        root=EMPTY_ROOT,
        signed_at=datetime.datetime(2026, 9, 7, 12, 0),  # Naive on purpose.
        signature=b"\x00" * 64,
    )

    assert not verify_checkpoint(checkpoint, key=Ed25519PrivateKey.generate().public_key())


def rejected_verdict(**overrides: object) -> object:
    """Return a resolved verdict for a document that fails a fixed rule."""
    item = evidence(Rung.DETERMINISTIC, Result.FAIL, **overrides)
    return resolve([item], provenance=provenance(), decided_at=DECIDED_AT)


def test_a_replayed_case_matches_what_the_log_recorded() -> None:
    """The claim the ledger exists to support, checked directly."""
    log = TransparencyLog()
    index = log.record(rejected_verdict(), case_id="case-1", recorded_at=DECIDED_AT)

    assert log.matches(rejected_verdict(), index=index)


def test_a_slower_replay_still_matches() -> None:
    """`runtime_ms` differs on every run and is not part of the decision.

    Committing to it would mean an honest replay never matched its own log
    entry, which would make the check useless and train an operator to ignore
    it.
    """
    log = TransparencyLog()
    index = log.record(rejected_verdict(runtime_ms=1.0), case_id="case-1", recorded_at=DECIDED_AT)

    assert log.matches(rejected_verdict(runtime_ms=94.5), index=index)


def test_a_replay_under_a_different_model_does_not_match() -> None:
    """A different model is a different basis for the decision, and must show."""
    log = TransparencyLog()
    index = log.record(
        rejected_verdict(model_version="rules/1"), case_id="case-1", recorded_at=DECIDED_AT
    )

    assert not log.matches(rejected_verdict(model_version="rules/2"), index=index)


def test_a_different_decision_does_not_match() -> None:
    """The obvious case, stated so a regression in digesting cannot hide."""
    log = TransparencyLog()
    index = log.record(rejected_verdict(), case_id="case-1", recorded_at=DECIDED_AT)
    cleared = resolve(
        [evidence(Rung.CRYPTOGRAPHIC, Result.PROOF_VALID)],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )

    assert not log.matches(cleared, index=index)


def test_matching_against_an_absent_entry_is_false() -> None:
    """An index that was never written proves nothing, and says so."""
    assert not TransparencyLog().matches(rejected_verdict(), index=0)


def test_the_canonical_form_is_stable() -> None:
    """Two serialisations of one verdict must be byte-identical, or replay fails."""
    assert canonical_verdict_bytes(rejected_verdict()) == canonical_verdict_bytes(
        rejected_verdict()
    )


def test_the_canonical_form_drops_runtime_but_keeps_the_model() -> None:
    """Pinned as text, because which fields are excluded is the whole design."""
    body = canonical_verdict_bytes(rejected_verdict(model_version="rules/7")).decode()

    assert "runtime_ms" not in body
    assert "rules/7" in body


def test_a_log_rebuilds_from_its_entries() -> None:
    """A restart must reach the same root, or every published checkpoint breaks."""
    original = TransparencyLog()
    for number in range(5):
        original.record(rejected_verdict(), case_id=f"case-{number}", recorded_at=DECIDED_AT)

    rebuilt = TransparencyLog(list(original.entries()))

    assert rebuilt.root() == original.root()
    assert len(rebuilt) == 5


def test_a_logs_own_proofs_verify_against_its_checkpoint() -> None:
    """End to end: record, checkpoint, then prove an entry to a third party."""
    key = Ed25519PrivateKey.generate()
    log = TransparencyLog()
    for number in range(7):
        log.record(rejected_verdict(), case_id=f"case-{number}", recorded_at=DECIDED_AT)
    checkpoint = log.checkpoint(key=key, signed_at=SIGNED_AT)

    assert verify_checkpoint(checkpoint, key=key.public_key())
    assert verify_inclusion(
        log.leaf(4), index=4, size=checkpoint.tree_size, proof=log.proof(4), root=checkpoint.root
    )


def test_an_entry_hashes_from_all_three_of_its_fields() -> None:
    """Case, digest and time all bind, so no entry can be re-pointed later."""
    base = LedgerEntry("case-1", "a" * 64, DECIDED_AT)
    others = [
        LedgerEntry("case-2", "a" * 64, DECIDED_AT),
        LedgerEntry("case-1", "b" * 64, DECIDED_AT),
        LedgerEntry("case-1", "a" * 64, DECIDED_AT + datetime.timedelta(seconds=1)),
    ]

    assert len({entry.canonical_bytes() for entry in [base, *others]}) == 4


def test_the_narrow_entry_point_agrees_with_the_log() -> None:
    """`append_entry` is the backend-agnostic hook named in the roadmap."""
    assert append_entry(b"payload") == leaf_hash(b"payload").hex()
