"""Publishing a checkpoint, and checking it the way a third party would.

ADR 0003 says an unpublished checkpoint proves nothing. These tests cover the
publishing command and, more importantly, `tools/verify_checkpoint.py` — the
file a recipient runs without any of this system.

**The load-bearing test is `test_the_standalone_verifier_agrees_with_the_system`.**
The verifier re-implements the checkpoint byte layout rather than importing it,
because a check that shares code with the thing it checks agrees with it by
construction. That independence is only worth having if the two are pinned
together, and this is where they are pinned.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import pathlib
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from api import publish_checkpoint
from core.contracts import Result, Rung
from core.trust.ladder import resolve
from db.recording import load_log, record_screening
from db.session import create_session_factory
from ledger.hashchain import signed_checkpoint_bytes, verify_consistency
from tests.support import DECIDED_AT, evidence, provenance

WHEN = datetime.datetime(2026, 9, 8, 12, 0, tzinfo=datetime.UTC)
"""When the cases in these tests were recorded."""


def verifier() -> ModuleType:
    """Load `tools/verify_checkpoint.py` the way a recipient would: as a lone file."""
    path = pathlib.Path("tools/verify_checkpoint.py")
    spec = importlib.util.spec_from_file_location("verify_checkpoint", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def signing_key(tmp_path: pathlib.Path) -> pathlib.Path:
    """Write an Ed25519 signing key and return its path."""
    path = tmp_path / "ledger.pem"
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path


@pytest.fixture
def database(tmp_path: pathlib.Path) -> str:
    """Return a database URL holding two recorded screenings."""
    url = f"sqlite+pysqlite:///{(tmp_path / 'ledger.db').as_posix()}"
    factory = create_session_factory(url, create=True)
    verdict = resolve(
        [evidence(Rung.DETERMINISTIC, Result.PASS)],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )
    with factory() as session:
        for index in (1, 2):
            record_screening(
                session,
                case_id=f"case-{index}",
                verdict=verdict,
                checkpoint_id="raxaul-03",
                recorded_at=WHEN,
            )
    return url


def publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    *,
    database: str,
    signing_key: pathlib.Path | None,
    out: str | None = None,
) -> int:
    """Run the publishing command with an environment, and return its exit code."""
    monkeypatch.setenv("SENTINELID_DB_URL", database)
    monkeypatch.setenv("SENTINELID_CHECKPOINT_ID", "raxaul-03")
    if signing_key is not None:
        monkeypatch.setenv("SENTINELID_LEDGER_KEY_FILE", str(signing_key))
    else:
        monkeypatch.delenv("SENTINELID_LEDGER_KEY_FILE", raising=False)
    folder = out or str(tmp_path / "published")
    return publish_checkpoint.main(["--out", folder])


def only_checkpoint(folder: pathlib.Path) -> dict[str, Any]:
    """Return the single checkpoint written into a folder."""
    files = sorted(folder.glob("*.json"))
    assert len(files) == 1, f"expected one checkpoint, found {files}"
    loaded: dict[str, Any] = json.loads(files[0].read_text(encoding="utf-8"))
    return loaded


# Publishing


def test_a_checkpoint_is_written_to_a_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """The criterion. Until a checkpoint can leave the box, the log proves nothing."""
    code = publish(monkeypatch, tmp_path, database=database, signing_key=signing_key)

    assert code == 0
    document = only_checkpoint(tmp_path / "published")
    assert document["tree_size"] == 2
    assert document["checkpoint_id"] == "raxaul-03"


def test_the_published_file_carries_everything_a_recipient_needs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """A recipient must depend on nothing the operator holds, including the key."""
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key)
    document = only_checkpoint(tmp_path / "published")

    for field in ("format", "checkpoint_id", "tree_size", "root", "signed_at", "signature"):
        assert document[field], f"{field} is missing or empty"
    assert document["public_key"], "without the key the file cannot be checked at all"


def test_publishing_without_a_signing_key_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unsigned substitute would look like proof, so none is written."""
    code = publish(monkeypatch, tmp_path, database=database, signing_key=None)

    assert code == publish_checkpoint.REFUSED
    assert not (tmp_path / "published").exists()
    assert "no signing key" in capsys.readouterr().err


def test_an_empty_log_still_publishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path, signing_key: pathlib.Path
) -> None:
    """That the log was empty at a time is itself a fact worth being able to prove."""
    url = f"sqlite+pysqlite:///{(tmp_path / 'empty.db').as_posix()}"
    create_session_factory(url, create=True)

    code = publish(monkeypatch, tmp_path, database=url, signing_key=signing_key)

    assert code == 0
    assert only_checkpoint(tmp_path / "published")["tree_size"] == 0


# The standalone verifier


def test_the_standalone_verifier_agrees_with_the_system() -> None:
    """The verifier re-implements the byte layout. This is what stops it drifting.

    If this fails, either the system changed its checkpoint format or the
    verifier did, and every checkpoint already published is about to stop
    verifying for somebody who is holding it.
    """
    tool = verifier()
    when = datetime.datetime(2026, 9, 8, 12, 0, tzinfo=datetime.UTC)
    root = bytes(range(32))

    assert tool.signed_bytes(7, root.hex(), when.isoformat()) == signed_checkpoint_bytes(
        7, root, when
    )


def test_the_verifier_accepts_a_real_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """End to end: this system publishes, and the standalone file accepts it."""
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key)
    published = sorted((tmp_path / "published").glob("*.json"))

    assert verifier().main([str(published[0])]) == 0


def test_the_verifier_rejects_a_tampered_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """Changing the root after signing is exactly what this must catch."""
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key)
    path = sorted((tmp_path / "published").glob("*.json"))[0]
    document = json.loads(path.read_text(encoding="utf-8"))
    document["root"] = "00" * 32
    path.write_text(json.dumps(document), encoding="utf-8")

    assert verifier().main([str(path)]) == 1


def test_the_verifier_rejects_a_changed_entry_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """Understating how many crossings happened is the interesting lie."""
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key)
    path = sorted((tmp_path / "published").glob("*.json"))[0]
    document = json.loads(path.read_text(encoding="utf-8"))
    document["tree_size"] = 1
    path.write_text(json.dumps(document), encoding="utf-8")

    assert verifier().main([str(path)]) == 1


def test_the_verifier_refuses_an_unknown_format(tmp_path: pathlib.Path) -> None:
    """A future layout must not be checked with today's rules and passed."""
    path = tmp_path / "future.json"
    path.write_text(
        json.dumps(
            {
                "format": "sentinelid-checkpoint-v2",
                "checkpoint_id": "raxaul-03",
                "tree_size": 1,
                "root": "00" * 32,
                "signed_at": "2026-09-08T12:00:00+00:00",
                "signature": "00" * 64,
                "public_key": "00" * 32,
            }
        ),
        encoding="utf-8",
    )

    assert verifier().main([str(path)]) == 1


def test_the_verifier_refuses_an_incomplete_file(tmp_path: pathlib.Path) -> None:
    """A file missing the key or the signature cannot be checked at all."""
    path = tmp_path / "partial.json"
    path.write_text(json.dumps({"format": "sentinelid-checkpoint-v1"}), encoding="utf-8")

    assert verifier().main([str(path)]) == 1


# What a series shows


def series(
    folder: pathlib.Path,
    sizes: list[int],
    key: Ed25519PrivateKey,
    roots: list[bytes] | None = None,
) -> list[pathlib.Path]:
    """Write a series of genuinely signed checkpoints with chosen sizes and roots.

    Every signature is real, so the series checks below are testing the series
    logic rather than accidentally testing signature verification again.
    """
    folder.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for index, size in enumerate(sizes):
        when = WHEN + datetime.timedelta(days=index)
        root = roots[index] if roots is not None else bytes([size]) * 32
        signature = key.sign(signed_checkpoint_bytes(size, root, when))
        document = publish_checkpoint.checkpoint_document(
            checkpoint_id="raxaul-03",
            tree_size=size,
            root=root.hex(),
            signed_at=when,
            signature=signature.hex(),
            public_key=key.public_key().public_bytes_raw().hex(),
        )
        path = folder / f"checkpoint-{index}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        written.append(path)
    return written


def test_a_growing_series_is_accepted(tmp_path: pathlib.Path) -> None:
    """An append-only log grows, and a recipient holding several can see that."""
    key = Ed25519PrivateKey.generate()
    paths = series(tmp_path / "series", [2, 5, 9], key)

    assert verifier().main([str(path) for path in paths]) == 0


def test_a_shrinking_series_is_reported(tmp_path: pathlib.Path) -> None:
    """Entries were removed. This is the whole reason the log exists."""
    key = Ed25519PrivateKey.generate()
    paths = series(tmp_path / "series", [2, 9, 5], key)

    assert verifier().main([str(path) for path in paths]) == 1


def test_a_rewritten_history_is_reported(tmp_path: pathlib.Path) -> None:
    """Same number of entries, different root: the past was edited, not extended."""
    key = Ed25519PrivateKey.generate()
    paths = series(tmp_path / "series", [4, 4], key, roots=[bytes([0xAA]) * 32, bytes([0xBB]) * 32])

    assert verifier().main([str(path) for path in paths]) == 1


# Consistency between published checkpoints


def add_case(url: str, case_id: str) -> None:
    """Append one more screening to a log, so the next checkpoint is larger."""
    factory = create_session_factory(url)
    verdict = resolve(
        [evidence(Rung.DETERMINISTIC, Result.PASS)],
        provenance=provenance(),
        decided_at=DECIDED_AT,
    )
    with factory() as session:
        record_screening(
            session,
            case_id=case_id,
            verdict=verdict,
            checkpoint_id="raxaul-03",
            recorded_at=WHEN,
        )


def test_a_checkpoint_can_prove_it_extends_the_previous_one(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """The claim an inclusion proof cannot make: nothing earlier was withdrawn."""
    first_dir = tmp_path / "first"
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key, out=str(first_dir))
    first = sorted(first_dir.glob("*.json"))[0]

    add_case(database, "case-3")
    second_dir = tmp_path / "second"
    monkeypatch.setenv("SENTINELID_DB_URL", database)
    monkeypatch.setenv("SENTINELID_CHECKPOINT_ID", "raxaul-03")
    monkeypatch.setenv("SENTINELID_LEDGER_KEY_FILE", str(signing_key))
    assert publish_checkpoint.main(["--out", str(second_dir), "--since", str(first)]) == 0

    second = sorted(second_dir.glob("*.json"))[0]
    document = json.loads(second.read_text(encoding="utf-8"))
    assert document["consistency"]["from_size"] == 2
    assert document["tree_size"] == 3

    assert verifier().main([str(first), str(second)]) == 0


def test_the_verifier_reports_a_proved_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A recipient must be able to see which links were proved and which were not."""
    first_dir = tmp_path / "first"
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key, out=str(first_dir))
    first = sorted(first_dir.glob("*.json"))[0]

    add_case(database, "case-3")
    second_dir = tmp_path / "second"
    publish_checkpoint.main(["--out", str(second_dir), "--since", str(first)])
    second = sorted(second_dir.glob("*.json"))[0]

    capsys.readouterr()
    verifier().main([str(first), str(second)])

    assert "PROVED to extend the previous checkpoint" in capsys.readouterr().out


def test_a_checkpoint_without_since_says_it_carries_no_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Silence about a missing proof would read as a proof that passed."""
    first_dir = tmp_path / "first"
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key, out=str(first_dir))
    add_case(database, "case-3")
    second_dir = tmp_path / "second"
    publish_checkpoint.main(["--out", str(second_dir)])

    capsys.readouterr()
    verifier().main(
        [
            str(sorted(first_dir.glob("*.json"))[0]),
            str(sorted(second_dir.glob("*.json"))[0]),
        ]
    )

    assert "carries no proof" in capsys.readouterr().out


def test_a_forged_consistency_proof_is_caught(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """The whole point. A proof that does not hold must not pass as one."""
    first_dir = tmp_path / "first"
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key, out=str(first_dir))
    first = sorted(first_dir.glob("*.json"))[0]

    add_case(database, "case-3")
    second_dir = tmp_path / "second"
    publish_checkpoint.main(["--out", str(second_dir), "--since", str(first)])
    second = sorted(second_dir.glob("*.json"))[0]

    document = json.loads(second.read_text(encoding="utf-8"))
    document["consistency"]["proof"] = ["00" * 32]
    second.write_text(json.dumps(document), encoding="utf-8")

    assert verifier().main([str(first), str(second)]) == 1


def test_a_proof_about_a_different_earlier_log_is_caught(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """A proof naming an earlier root that is not the one held proves nothing."""
    first_dir = tmp_path / "first"
    publish(monkeypatch, tmp_path, database=database, signing_key=signing_key, out=str(first_dir))
    first = sorted(first_dir.glob("*.json"))[0]

    add_case(database, "case-3")
    second_dir = tmp_path / "second"
    publish_checkpoint.main(["--out", str(second_dir), "--since", str(first)])
    second = sorted(second_dir.glob("*.json"))[0]

    document = json.loads(second.read_text(encoding="utf-8"))
    document["consistency"]["from_root"] = "11" * 32
    second.write_text(json.dumps(document), encoding="utf-8")

    assert verifier().main([str(first), str(second)]) == 1


def test_publishing_against_a_larger_earlier_checkpoint_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A log smaller than one it claims to extend has lost entries. Say so, loudly."""
    invented = tmp_path / "invented.json"
    invented.write_text(
        json.dumps(
            publish_checkpoint.checkpoint_document(
                checkpoint_id="raxaul-03",
                tree_size=99,
                root="00" * 32,
                signed_at=WHEN,
                signature="00" * 64,
                public_key="00" * 32,
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("SENTINELID_DB_URL", database)
    monkeypatch.setenv("SENTINELID_CHECKPOINT_ID", "raxaul-03")
    monkeypatch.setenv("SENTINELID_LEDGER_KEY_FILE", str(signing_key))
    code = publish_checkpoint.main(["--out", str(tmp_path / "out"), "--since", str(invented)])

    assert code == publish_checkpoint.REFUSED
    assert "cannot be an extension" in capsys.readouterr().err


def test_the_consistency_endpoint_matches_the_published_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    database: str,
    signing_key: pathlib.Path,
) -> None:
    """The online path and the offline path must not disagree about the same log."""
    factory = create_session_factory(database)
    with factory() as session:
        log = load_log(session)
        proof = log.consistency(1)
        root = log.root()

    assert verify_consistency(
        old_size=1,
        new_size=len(log),
        old_root=log.leaf(0),
        new_root=root,
        proof=proof,
    )
