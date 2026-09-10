"""Face embeddings: encrypted at rest, dated, and never called anonymous.

Rule 4 of CLAUDE.md in three parts. The last test in this file is the one that
matters most: it scans every file in the repository and fails on any sentence
describing an embedding with a word that is not true of it. Those words are
listed in `FORBIDDEN` below rather than here, so that this docstring does not
have to contain the assertion it exists to prevent.
"""

from __future__ import annotations

import datetime
import pathlib
import re
from typing import Final

import pytest
from pydantic import ValidationError

from core.privacy.biometrics import (
    KEY_BYTES,
    NONCE_BYTES,
    BiometricKey,
    BiometricKeyError,
    EncryptedEmbedding,
    decrypt_embedding,
    encrypt_embedding,
)
from core.privacy.retention import ArtefactCategory, RetentionPolicy
from tests.support import committed_text_files

VECTOR: Final[tuple[float, ...]] = tuple(0.01 * index for index in range(512))
MADE_AT: Final[datetime.datetime] = datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.UTC)
MODEL: Final[str] = "buffalo_l/1.0.0"


def stored(key: BiometricKey | None = None) -> EncryptedEmbedding:
    """Encrypt the standard test vector."""
    return encrypt_embedding(
        VECTOR, key=key or BiometricKey.generate(), created_at=MADE_AT, model_version=MODEL
    )


def policy(days: int = 7) -> RetentionPolicy:
    """Build a complete retention policy with a given face embedding window."""
    windows = dict.fromkeys(ArtefactCategory, datetime.timedelta(days=365))
    windows[ArtefactCategory.FACE_EMBEDDING] = datetime.timedelta(days=days)
    return RetentionPolicy(windows=windows)


# ---------------------------------------------------------------------------
# Encrypted at rest
# ---------------------------------------------------------------------------


def test_an_embedding_round_trips() -> None:
    """The ordinary path: what goes in comes back out."""
    key = BiometricKey.generate()

    assert decrypt_embedding(stored(key), key=key) == pytest.approx(VECTOR)


def test_the_stored_record_does_not_contain_the_vector() -> None:
    """Stated as a test because it is the whole point of the module."""
    record = stored()
    plain = b"".join(str(value).encode() for value in VECTOR[:8])

    assert plain not in record.ciphertext
    assert len(record.ciphertext) > 0


def test_a_different_key_cannot_read_it() -> None:
    """An embedding taken without the key is not readable."""
    record = stored()

    with pytest.raises(BiometricKeyError, match="cannot be decrypted"):
        decrypt_embedding(record, key=BiometricKey.generate())


def test_every_record_uses_a_fresh_nonce() -> None:
    """Reusing a nonce under one key would destroy the encryption entirely."""
    key = BiometricKey.generate()
    nonces = {stored(key).nonce for _ in range(16)}

    assert len(nonces) == 16
    assert all(len(nonce) == NONCE_BYTES for nonce in nonces)


def test_the_same_vector_encrypts_differently_every_time() -> None:
    """Otherwise two identical embeddings would be linkable without the key."""
    key = BiometricKey.generate()

    assert stored(key).ciphertext != stored(key).ciphertext


def test_an_empty_embedding_is_refused() -> None:
    """A record that decrypts to nothing is a bug stored for later."""
    with pytest.raises(BiometricKeyError, match="empty embedding"):
        encrypt_embedding((), key=BiometricKey.generate(), created_at=MADE_AT, model_version=MODEL)


def test_a_short_key_is_refused() -> None:
    """Accepted with a warning is not a thing this module does."""
    with pytest.raises(BiometricKeyError, match=f"exactly {KEY_BYTES} bytes"):
        BiometricKey(b"too short")


def test_a_key_never_appears_in_its_own_repr() -> None:
    """A key swept into a traceback would undo the encryption."""
    key = BiometricKey(b"k" * KEY_BYTES)

    assert repr(key) == "BiometricKey(<redacted>)"
    assert str(key) == "BiometricKey(<redacted>)"
    assert "kkkk" not in repr(key)


# ---------------------------------------------------------------------------
# What is bound into the ciphertext
# ---------------------------------------------------------------------------


def test_editing_the_creation_time_breaks_decryption() -> None:
    """The timestamp is authenticated, so a retention window cannot be quietly extended.

    Without this, the cheapest way to keep biometric data past its window would
    be to change one field in a database row.
    """
    key = BiometricKey.generate()
    record = stored(key)
    altered = record.model_copy(update={"created_at": MADE_AT + datetime.timedelta(days=3650)})

    with pytest.raises(BiometricKeyError):
        decrypt_embedding(altered, key=key)


def test_reinterpreting_a_record_under_another_model_breaks_decryption() -> None:
    """Vectors from two models are not comparable, so a record cannot be relabelled."""
    key = BiometricKey.generate()
    altered = stored(key).model_copy(update={"model_version": "some_other_model/1"})

    with pytest.raises(BiometricKeyError):
        decrypt_embedding(altered, key=key)


def test_a_record_is_frozen() -> None:
    """Stored biometric data is a record, not a working value."""
    record = stored()

    with pytest.raises(ValidationError):
        record.created_at = MADE_AT


def test_a_naive_timestamp_is_refused() -> None:
    """A record that cannot be aged cannot have a retention window enforced on it."""
    with pytest.raises(ValidationError, match="timezone aware"):
        EncryptedEmbedding(
            ciphertext=b"x",
            nonce=b"n" * NONCE_BYTES,
            created_at=datetime.datetime(2026, 1, 1, 12, 0),
            model_version=MODEL,
            dimension=8,
        )


def test_the_dimension_is_recorded_but_reveals_nothing() -> None:
    """Useful for validation, and not a property of anybody's face."""
    assert stored().dimension == len(VECTOR)


# ---------------------------------------------------------------------------
# Retention, enforced by code
# ---------------------------------------------------------------------------


def test_an_embedding_knows_when_it_must_be_destroyed() -> None:
    """The exit criterion for this phase: a window the code enforces, not a document."""
    record = stored()

    assert not record.is_due_for_deletion(policy=policy(7), now=MADE_AT)
    assert record.is_due_for_deletion(policy=policy(7), now=MADE_AT + datetime.timedelta(days=7))


def test_a_policy_cannot_omit_the_face_embedding_window() -> None:
    """A deployment cannot start with biometric retention left unanswered."""
    windows = dict.fromkeys(ArtefactCategory, datetime.timedelta(days=30))
    del windows[ArtefactCategory.FACE_EMBEDDING]

    with pytest.raises(ValidationError, match="FACE_EMBEDDING"):
        RetentionPolicy(windows=windows)


# ---------------------------------------------------------------------------
# The claim that must never appear
# ---------------------------------------------------------------------------

FORBIDDEN: Final[tuple[str, ...]] = (
    "irreversible",
    "one-way",
    "one way",
    "pii-free",
    "anonymous",
    "anonymised",
    "non-personal",
)
"""Words that must never be asserted of an embedding. They are all false."""

NEGATIONS: Final[tuple[str, ...]] = (
    "not",
    "never",
    "cannot",
    "forbid",
    "false",
    "avoid",
    "no ",
    # Identifiers separate words with underscores, so a function named
    # `test_no_file_describes...` denies the claim as clearly as prose does.
    "no_",
    "not_",
)
"""A sentence denying the claim is fine. A sentence making it is not."""

SCANNED: Final[frozenset[str]] = frozenset({".py", ".md", ".toml", ".cfg", ".json", ".yml"})

SKIPPED: Final[frozenset[str]] = frozenset(
    {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis"}
)

REPO: Final[pathlib.Path] = pathlib.Path(__file__).parents[2]
SENTENCE: Final[re.Pattern[str]] = re.compile(r"(?<=[.!?])\s+")
"""Splits sentences.

Only on a terminator followed by whitespace, so a full stop inside
``CLAUDE.md``, ``s.4.2.2`` or a version number does not end a sentence. An
earlier version split on every full stop and orphaned the word that
qualified the claim.
"""

WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")


def repository_files() -> list[pathlib.Path]:
    """Return every committed text file worth scanning.

    Asks git rather than walking the tree. This scan was previously missing
    `.import_linter_cache` from its skip list and was reading a tool cache,
    which is the defect commit 340004a fixed in the other scan and not in this
    one. Enumerating what is committed removes the whole class of mistake
    rather than adding one more directory name to a list.
    """
    return committed_text_files(SCANNED)


FILES: Final[list[pathlib.Path]] = repository_files()


def test_the_scan_covers_the_repository() -> None:
    """A discovery bug that found nothing would make the guard below vacuous."""
    names = {path.relative_to(REPO).as_posix() for path in FILES}

    assert len(FILES) > 60
    assert "core/privacy/biometrics.py" in names
    assert "CLAUDE.md" in names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(REPO).as_posix())
def test_no_file_claims_an_embedding_is_anonymous(path: pathlib.Path) -> None:
    """Rule 4, enforced across every file rather than left to review.

    A face embedding is partially invertible: given the vector and the model, an
    approximation of the face can be reconstructed. Calling it irreversible or
    anonymous is not a simplification, it is wrong, and it is the sentence that
    ends up in a privacy assessment.

    A sentence that *denies* the claim is fine — this file is full of them.
    """
    # Whitespace is normalised first. Prose is wrapped across lines, and a
    # line-bounded scan splits a sentence away from the negation that qualifies
    # it: an earlier version flagged `core/privacy/hashing.py` for a sentence
    # whose "forbids" sat on the following line.
    text = WHITESPACE.sub(" ", path.read_text(encoding="utf-8", errors="ignore"))

    for sentence in SENTENCE.split(text):
        if "embedding" not in sentence.lower():
            continue
        lowered = sentence.lower()
        claimed = [word for word in FORBIDDEN if word in lowered]
        if not claimed:
            continue
        assert any(negation in lowered for negation in NEGATIONS), (
            f"{path.relative_to(REPO).as_posix()} appears to claim an embedding is "
            f"{claimed}: {sentence.strip()!r}"
        )
