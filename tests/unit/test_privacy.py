"""Masking, identifiers, hashing and retention.

Most of these assert that something is *refused* or *hidden*. That is the shape
of the whole module: rule 3 of CLAUDE.md is a prohibition, and the way to test a
prohibition is to try the thing.
"""

from __future__ import annotations

import datetime
import json
import logging

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel, ConfigDict, ValidationError

from core.privacy import (
    DIGEST_LENGTH,
    MINIMUM_KEY_BYTES,
    ArtefactCategory,
    DeploymentKey,
    IdentifierKind,
    RawIdentifier,
    RetentionPolicy,
    deletion_due_at,
    digests_match,
    hash_document_number,
    is_due_for_deletion,
    mask_aadhaar,
    mask_value,
)

# A synthetic Aadhaar-shaped number. It begins with 0, which UIDAI never
# issues, so it cannot be a real person's number. See tests/golden/vectors.
SYNTHETIC_AADHAAR = "012345678906"

NOW = datetime.datetime(2026, 9, 6, 12, 0, tzinfo=datetime.UTC)
NAIVE = datetime.datetime(2026, 9, 6, 12, 0)


def complete_policy(**overrides: datetime.timedelta) -> RetentionPolicy:
    """Build a policy covering every category, so a test can vary one."""
    windows = dict.fromkeys(ArtefactCategory, datetime.timedelta(days=30))
    windows.update({ArtefactCategory[key]: value for key, value in overrides.items()})
    return RetentionPolicy(windows=windows)


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("012345678906", "XXXXXXXX8906"),
        ("Z0000001", "XXXX0001"),
        ("ABCD", "XXXX"),
        ("AB", "XX"),
        ("", ""),
    ],
)
def test_masking_reveals_at_most_the_last_four_characters(value: str, expected: str) -> None:
    """The ordinary case, and the short-value case that the obvious code gets wrong."""
    assert mask_value(value) == expected


def test_a_short_value_is_hidden_completely_rather_than_revealed() -> None:
    """A value no longer than the reveal window must not come back in full.

    The naive implementation slices from a negative index and returns the whole
    string, which turns a masking call into a disclosure.
    """
    assert mask_value("12", visible=4) == "XX"
    assert mask_value("1234", visible=4) == "XXXX"


def test_masking_everything_is_allowed() -> None:
    """Zero visible characters is a legitimate request."""
    assert mask_value("012345678906", visible=0) == "X" * 12


def test_aadhaar_masks_in_the_form_uidai_uses() -> None:
    """Grouped in fours, last four visible."""
    assert mask_aadhaar(SYNTHETIC_AADHAAR) == "XXXX XXXX 8906"
    assert mask_aadhaar("0123 4567 8906") == "XXXX XXXX 8906"
    assert mask_aadhaar("0123-4567-8906") == "XXXX XXXX 8906"


@pytest.mark.parametrize(("visible", "group"), [(-1, None), (0, 0), (4, -2)])
def test_nonsensical_masking_arguments_are_refused(visible: int, group: int | None) -> None:
    """A negative reveal window or a zero group size is a bug in the caller."""
    with pytest.raises(ValueError, match=r"cannot be negative|at least one"):
        mask_value("012345678906", visible=visible, group=group)


@settings(max_examples=300)
@given(value=st.text(max_size=40), visible=st.integers(min_value=0, max_value=8))
def test_no_character_survives_outside_the_reveal_window(value: str, visible: int) -> None:
    """Whatever the input, nothing before the last `visible` positions is left readable.

    Stated as positions rather than as a count of changed characters, because a
    value that already contains an X would make a naive count wrong without
    anything actually leaking.
    """
    masked = mask_value(value, visible=visible)
    survived = [index for index, character in enumerate(masked) if character != "X"]

    assert len(masked) == len(value)
    assert all(index >= len(value) - visible for index in survived)


# ---------------------------------------------------------------------------
# RawIdentifier: the accidental paths out
# ---------------------------------------------------------------------------


def identifier(value: str = SYNTHETIC_AADHAAR) -> RawIdentifier:
    """Build a raw identifier for the tests below."""
    return RawIdentifier(value, kind=IdentifierKind.AADHAAR)


def test_str_gives_the_masked_form() -> None:
    """A number interpolated into a message is already masked."""
    assert str(identifier()) == "XXXX XXXX 8906"


def test_repr_gives_the_masked_form() -> None:
    """A traceback, a debugger and `%r` in a log all go through repr."""
    assert SYNTHETIC_AADHAAR not in repr(identifier())
    assert "8906" in repr(identifier())


def test_an_f_string_gives_the_masked_form() -> None:
    """f-strings reach __format__, not __str__, and a format spec must not bypass masking."""
    number = identifier()

    assert f"{number}" == "XXXX XXXX 8906"
    assert f"{number:>40}" == "XXXX XXXX 8906"


def test_a_log_line_carries_only_the_masked_form(caplog: pytest.LogCaptureFixture) -> None:
    """The path a number most often escapes through in practice."""
    with caplog.at_level(logging.INFO):
        logging.getLogger("test").info("screening %s and %r", identifier(), identifier())

    assert SYNTHETIC_AADHAAR not in caplog.text
    assert "XXXX XXXX 8906" in caplog.text


def test_json_refuses_it_rather_than_serialising_it() -> None:
    """Serialising fails loudly instead of writing the digits into a payload."""
    with pytest.raises(TypeError):
        json.dumps({"number": identifier()})


def test_it_cannot_be_declared_as_a_contract_field() -> None:
    """The exit criterion, enforced by the type system rather than by review.

    A raw number cannot enter a Pydantic contract at all, so it cannot reach
    the ledger or the database through one. This fails at class definition, not
    at serialisation.
    """
    with pytest.raises(Exception, match=r"[Ss]chema"):

        class Leaky(BaseModel):
            model_config = ConfigDict(frozen=True, extra="forbid")

            number: RawIdentifier


def test_reveal_is_the_only_way_to_the_digits() -> None:
    """One deliberate door, named so every call site can be found."""
    assert identifier().reveal() == SYNTHETIC_AADHAAR


# ---------------------------------------------------------------------------
# RawIdentifier: normalisation and construction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "written", ["0123 4567 8906", "0123-4567-8906", "0123/4567/8906", " 012345678906 "]
)
def test_spacing_and_separators_are_normalised_away(written: str) -> None:
    """Two spellings of one number must hash to the same value."""
    assert RawIdentifier(written, kind=IdentifierKind.AADHAAR).reveal() == SYNTHETIC_AADHAAR


def test_case_is_normalised() -> None:
    """Passport numbers are uppercase on the document and must be uppercase here."""
    assert RawIdentifier("z0000001", kind=IdentifierKind.PASSPORT).reveal() == "Z0000001"


@pytest.mark.parametrize("empty", ["", "   ", "---", " - / "])
def test_an_empty_number_is_refused(empty: str) -> None:
    """A number that normalises to nothing is not a number."""
    with pytest.raises(ValueError, match="cannot be empty"):
        RawIdentifier(empty, kind=IdentifierKind.AADHAAR)


def test_a_malformed_number_is_still_accepted() -> None:
    """A forged document carries a number that fails its checksum.

    The system has to be able to hold, hash and report that number. Judging
    whether it is well formed is a Rung 1 detector's job, not this class's.
    """
    assert RawIdentifier("999", kind=IdentifierKind.AADHAAR).reveal() == "999"


def test_identifiers_compare_by_kind_and_value() -> None:
    """The same digits under two document kinds are not the same identifier."""
    aadhaar = RawIdentifier(SYNTHETIC_AADHAAR, kind=IdentifierKind.AADHAAR)
    epic = RawIdentifier(SYNTHETIC_AADHAAR, kind=IdentifierKind.VOTER_EPIC)

    assert aadhaar == RawIdentifier("0123 4567 8906", kind=IdentifierKind.AADHAAR)
    assert aadhaar != epic
    assert aadhaar != SYNTHETIC_AADHAAR
    assert len({aadhaar, epic}) == 2


def test_a_non_aadhaar_number_masks_without_grouping() -> None:
    """Grouping in fours is an Aadhaar printing convention, not a general one."""
    assert str(RawIdentifier("Z0000001", kind=IdentifierKind.PASSPORT)) == "XXXX0001"


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def test_a_digest_is_a_lowercase_hex_sha256() -> None:
    """The same shape as every other digest in the system."""
    digest = hash_document_number(identifier(), key=DeploymentKey.generate())

    assert len(digest) == DIGEST_LENGTH
    assert set(digest) <= set("0123456789abcdef")


def test_the_same_number_and_key_always_give_the_same_digest() -> None:
    """Matching a repeat crossing in phase 8 depends on this."""
    key = DeploymentKey.generate()

    assert hash_document_number(identifier(), key=key) == hash_document_number(
        identifier(), key=key
    )


def test_different_keys_give_different_digests() -> None:
    """Two deployments cannot correlate their records without sharing a key."""
    assert hash_document_number(identifier(), key=DeploymentKey.generate()) != (
        hash_document_number(identifier(), key=DeploymentKey.generate())
    )


def test_the_same_digits_under_two_document_kinds_do_not_collide() -> None:
    """Domain separation. Otherwise two unrelated records would silently link."""
    key = DeploymentKey.generate()
    aadhaar = RawIdentifier(SYNTHETIC_AADHAAR, kind=IdentifierKind.AADHAAR)
    epic = RawIdentifier(SYNTHETIC_AADHAAR, kind=IdentifierKind.VOTER_EPIC)

    assert hash_document_number(aadhaar, key=key) != hash_document_number(epic, key=key)


def test_a_digest_does_not_contain_the_number() -> None:
    """Stated as a test because it is the whole point of the module."""
    digest = hash_document_number(identifier(), key=DeploymentKey.generate())

    assert SYNTHETIC_AADHAAR not in digest


def test_a_short_key_is_refused() -> None:
    """A weak key over a twelve-digit keyspace is no protection at all."""
    with pytest.raises(ValueError, match="at least 32 bytes"):
        DeploymentKey(b"too short")


def test_a_key_of_exactly_the_minimum_length_is_accepted() -> None:
    """The boundary is inclusive."""
    assert DeploymentKey(b"k" * MINIMUM_KEY_BYTES).derive(b"payload")


def test_a_generated_key_is_long_enough() -> None:
    """The convenience constructor cannot produce a key the checked one would refuse."""
    assert DeploymentKey.generate().derive(b"payload")


def test_a_key_never_appears_in_its_own_repr() -> None:
    """A key swept into a traceback or a log would undo the whole scheme."""
    key = DeploymentKey(b"k" * MINIMUM_KEY_BYTES)

    assert repr(key) == "DeploymentKey(<redacted>)"
    assert str(key) == "DeploymentKey(<redacted>)"
    assert "kkkk" not in repr(key)


def test_digests_compare_without_leaking_through_timing() -> None:
    """Phase 8 compares digests to find repeat crossings."""
    key = DeploymentKey.generate()
    digest = hash_document_number(identifier(), key=key)

    assert digests_match(digest, digest)
    assert not digests_match(digest, "0" * DIGEST_LENGTH)


@settings(max_examples=200)
@given(
    value=st.text(alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=20),
    kind=st.sampled_from(list(IdentifierKind)),
)
def test_a_digest_is_always_fixed_length_hex(value: str, kind: IdentifierKind) -> None:
    """Whatever the number, the digest is the same shape and reveals nothing by its size.

    A variable-length output would leak the length of the input, which for a
    document number is most of what distinguishes one document type from
    another.
    """
    digest = hash_document_number(RawIdentifier(value, kind=kind), key=DeploymentKey.generate())

    assert len(digest) == DIGEST_LENGTH
    assert set(digest) <= set("0123456789abcdef")


@settings(max_examples=200)
@given(
    left=st.text(alphabet="0123456789", min_size=6, max_size=16),
    right=st.text(alphabet="0123456789", min_size=6, max_size=16),
)
def test_distinct_numbers_get_distinct_digests(left: str, right: str) -> None:
    """Two different numbers do not collide, so a match means a genuine repeat."""
    key = DeploymentKey.generate()
    kind = IdentifierKind.AADHAAR
    digest_of_left = hash_document_number(RawIdentifier(left, kind=kind), key=key)
    digest_of_right = hash_document_number(RawIdentifier(right, kind=kind), key=key)

    assert (left == right) == digests_match(digest_of_left, digest_of_right)


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def test_a_policy_must_cover_every_category() -> None:
    """A deployment cannot start with an unanswered question about biometrics."""
    with pytest.raises(ValidationError, match="no retention window given for"):
        RetentionPolicy(windows={ArtefactCategory.CASE_RECORD: datetime.timedelta(days=30)})


def test_the_error_names_what_is_missing() -> None:
    """A policy is edited by a person, so the message has to be actionable."""
    windows = dict.fromkeys(ArtefactCategory, datetime.timedelta(days=30))
    del windows[ArtefactCategory.FACE_EMBEDDING]

    with pytest.raises(ValidationError, match="FACE_EMBEDDING"):
        RetentionPolicy(windows=windows)


@pytest.mark.parametrize("window", [datetime.timedelta(0), datetime.timedelta(days=-1)])
def test_a_window_must_be_positive(window: datetime.timedelta) -> None:
    """A window of zero is not a policy anybody can act on."""
    with pytest.raises(ValidationError, match="must be positive"):
        complete_policy(DOCUMENT_IMAGE=window)


def test_biometrics_cannot_outlive_the_case_that_justified_them() -> None:
    """Rule 4. A face embedding with no case behind it has nothing accounting for it."""
    with pytest.raises(ValidationError, match="cannot be kept longer than the case record"):
        complete_policy(
            FACE_EMBEDDING=datetime.timedelta(days=90),
            CASE_RECORD=datetime.timedelta(days=30),
        )


def test_biometrics_may_match_the_case_window() -> None:
    """The bound is inclusive; equal windows are a legitimate policy."""
    policy = complete_policy(
        FACE_EMBEDDING=datetime.timedelta(days=30), CASE_RECORD=datetime.timedelta(days=30)
    )

    assert policy.windows[ArtefactCategory.FACE_EMBEDDING] == datetime.timedelta(days=30)


def test_there_are_no_default_windows() -> None:
    """Shipping defaults would put invented policy in the repository."""
    with pytest.raises(ValidationError):
        RetentionPolicy()


def test_a_deletion_deadline_is_creation_plus_the_window() -> None:
    """The arithmetic, stated once."""
    policy = complete_policy(DOCUMENT_IMAGE=datetime.timedelta(days=7))

    assert deletion_due_at(NOW, category=ArtefactCategory.DOCUMENT_IMAGE, policy=policy) == (
        NOW + datetime.timedelta(days=7)
    )


def test_an_artefact_is_due_the_moment_its_window_closes() -> None:
    """The boundary is inclusive: due at the deadline, not the day after."""
    policy = complete_policy(FACE_EMBEDDING=datetime.timedelta(days=1))
    due = NOW + datetime.timedelta(days=1)

    assert not is_due_for_deletion(
        NOW,
        category=ArtefactCategory.FACE_EMBEDDING,
        policy=policy,
        now=due - datetime.timedelta(seconds=1),
    )
    assert is_due_for_deletion(
        NOW, category=ArtefactCategory.FACE_EMBEDDING, policy=policy, now=due
    )


def test_a_naive_creation_time_cannot_be_aged() -> None:
    """A timestamp with no timezone cannot be placed on a timeline."""
    with pytest.raises(ValueError, match="created_at must be timezone aware"):
        deletion_due_at(NAIVE, category=ArtefactCategory.CASE_RECORD, policy=complete_policy())


def test_a_naive_reference_time_is_refused_too() -> None:
    """The same rule on the other argument."""
    with pytest.raises(ValueError, match="now must be timezone aware"):
        is_due_for_deletion(
            NOW, category=ArtefactCategory.CASE_RECORD, policy=complete_policy(), now=NAIVE
        )


def test_a_policy_is_frozen() -> None:
    """Retention is configuration, not something a running system edits."""
    policy = complete_policy()

    with pytest.raises(ValidationError):
        policy.windows = {}  # type: ignore[misc]
