"""Configuration, and the three things this system will not guess.

A database, a checkpoint identity and a signing key all have wrong answers that
look like working ones: a second database nobody knows about, an audit record
stamped with the wrong crossing, and a checkpoint signed by a key generated at
start-up. Each would run, and each would be discovered by an auditor rather
than by an operator.

So there are no defaults for the first two, and the third degrades loudly. The
last test in this file is the one that matters most: an absent capability has
to reach the officer in a sentence, not sit in a log nobody reads.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from api import settings as settings_module
from api.settings import (
    DEFAULT_MAX_UPLOAD_BYTES,
    NO_HASH_KEY,
    NO_LEDGER_KEY,
    ConfigurationError,
    Settings,
    from_environment,
)
from tests.support import write_anchors_file

URL = "sqlite+pysqlite:///./test.db"


@pytest.fixture(autouse=True)
def _clear_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from an unconfigured machine."""
    for name in (
        settings_module.DATABASE_URL,
        settings_module.CHECKPOINT_ID,
        settings_module.HASH_KEY_FILE,
        settings_module.LEDGER_KEY_FILE,
        settings_module.MAX_UPLOAD_BYTES,
    ):
        monkeypatch.delenv(name, raising=False)


def write_ledger_key(folder: pathlib.Path) -> pathlib.Path:
    """Write an Ed25519 private key in the form a deployment mounts."""
    path = folder / "ledger.pem"
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path


def test_settings_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The ordinary path, so the refusals below are refusals of something real."""
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")
    monkeypatch.setenv(settings_module.HASH_KEY_FILE, str(_write_hash_key(tmp_path)))
    monkeypatch.setenv(settings_module.LEDGER_KEY_FILE, str(write_ledger_key(tmp_path)))
    monkeypatch.setenv(settings_module.RETENTION_POLICY_FILE, str(write_retention_policy(tmp_path)))
    monkeypatch.setenv(settings_module.TRUST_ANCHORS_FILE, str(write_anchors_file(tmp_path)))

    settings = from_environment()

    assert settings.database_url == URL
    assert settings.checkpoint_id == "raxaul-03"
    assert settings.hash_key is not None
    assert settings.ledger_key is not None
    assert settings.retention_policy is not None
    assert len(settings.trust_store) == 1
    assert settings.unavailable() == ()


def write_retention_policy(folder: pathlib.Path) -> pathlib.Path:
    """Write a complete retention policy. Incomplete ones are refused elsewhere."""
    path = folder / "retention.json"
    path.write_text(
        json.dumps(
            {
                "FACE_EMBEDDING": 7,
                "PORTRAIT_CROP": 7,
                "DOCUMENT_IMAGE": 14,
                "EVIDENCE_EXHIBIT": 14,
                "CASE_RECORD": 30,
                "LEDGER_ENTRY": 3650,
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_hash_key(folder: pathlib.Path) -> pathlib.Path:
    """Write a hashing key of the minimum accepted length."""
    path = folder / "hash.key"
    path.write_bytes(b"k" * 32)
    return path


def test_a_missing_database_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A default path would create a second database rather than use the real one."""
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")

    with pytest.raises(ConfigurationError, match=settings_module.DATABASE_URL):
        from_environment()


def test_a_missing_checkpoint_identity_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every audit record is stamped with it, so a placeholder would be a false one."""
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)

    with pytest.raises(ConfigurationError, match=settings_module.CHECKPOINT_ID):
        from_environment()


def test_whitespace_does_not_count_as_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """A variable set to a space is the mistake an env file makes most often."""
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "   ")

    with pytest.raises(ConfigurationError):
        from_environment()


def test_keys_are_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    """A checkpoint runs without them. It just cannot do everything, and says so."""
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")

    settings = from_environment()

    assert settings.hash_key is None
    assert settings.ledger_key is None
    assert settings.max_upload_bytes == DEFAULT_MAX_UPLOAD_BYTES


def test_an_upload_limit_can_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """A checkpoint on a slow link may want a smaller one."""
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")
    monkeypatch.setenv(settings_module.MAX_UPLOAD_BYTES, "4096")

    assert from_environment().max_upload_bytes == 4096


def test_an_unreadable_key_file_is_a_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """The operator meant to supply a key. Running on would hide that they had not.

    This is the one case where degrading would be wrong. An absent key is a
    deployment that has not been given one; an unreadable key is a deployment
    that thinks it has.
    """
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")
    monkeypatch.setenv(settings_module.LEDGER_KEY_FILE, "no-such-file.pem")

    with pytest.raises(ConfigurationError, match="cannot read the signing key"):
        from_environment()


def test_a_short_hashing_key_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The refusal comes from `DeploymentKey`; this checks it is not swallowed."""
    weak = tmp_path / "weak.key"
    weak.write_bytes(b"short")
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")
    monkeypatch.setenv(settings_module.HASH_KEY_FILE, str(weak))

    with pytest.raises(ConfigurationError, match="not usable"):
        from_environment()


def test_a_key_of_the_wrong_kind_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """An RSA key here is a mounting mistake, not a signing key with a quirk."""
    path = tmp_path / "rsa.pem"
    path.write_bytes(
        generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv(settings_module.DATABASE_URL, URL)
    monkeypatch.setenv(settings_module.CHECKPOINT_ID, "raxaul-03")
    monkeypatch.setenv(settings_module.LEDGER_KEY_FILE, str(path))

    with pytest.raises(ConfigurationError, match="not an Ed25519 key"):
        from_environment()


def test_what_is_missing_is_stated_in_officer_facing_sentences() -> None:
    """The honesty rule applied to the deployment itself.

    A capability that is quietly absent is the failure CLAUDE.md names. These
    sentences are what reaches the console's front page and every screening
    response, so they are checked for being sentences rather than flags.
    """
    missing = Settings(database_url=URL, checkpoint_id="raxaul-03").unavailable()

    assert NO_LEDGER_KEY in missing
    assert NO_HASH_KEY in missing
    for sentence in missing:
        assert sentence.endswith(".")
        assert len(sentence.split()) > 6
