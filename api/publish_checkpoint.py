"""Writing a signed checkpoint to a file, so it can leave this machine.

    python -m api.publish_checkpoint --out checkpoints/

ADR 0003 is explicit: **an unpublished checkpoint proves nothing.** Whoever
holds the database can recompute the entire Merkle chain, so a root this system
shows you is a number it chose. What makes the log worth anything is that a
statement about its contents was signed and handed to somebody else, at a time,
before there was any reason to want it changed.

Nothing here automates that handover, and that is deliberate. `CLAUDE.md`
forbids any cloud service, and a checkpoint uploaded by the operator to storage
the operator controls has not left the operator's control. What this command
produces is a small file to be carried off the box — copied to a second
organisation, emailed to a supervisor, printed and filed. The transfer is a
procedure, and procedures belong to the deployment, not to this repository.

**The file is self-describing.** It carries the public key and the checkpoint
identity alongside the signature, so a recipient needs nothing from this system
to check it — and `tools/verify_checkpoint.py` does exactly that, in a single
file with no import from this repository.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
from collections.abc import Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from api.settings import LEDGER_KEY_FILE, ConfigurationError, from_environment
from db.recording import load_log
from db.session import create_session_factory
from ledger.hashchain import verify_checkpoint

REFUSED: int = 2
"""Exit code for a checkpoint that could not be published."""

FORMAT: str = "sentinelid-checkpoint-v1"
"""Names the byte layout the signature covers, so a verifier can refuse others."""


def checkpoint_document(
    *,
    checkpoint_id: str,
    tree_size: int,
    root: str,
    signed_at: datetime.datetime,
    signature: str,
    public_key: str,
) -> dict[str, object]:
    """Return the published form of a checkpoint.

    Args:
        checkpoint_id: Which crossing point signed it.
        tree_size: How many entries the log held.
        root: The Merkle root, hex encoded.
        signed_at: When it was signed.
        signature: The Ed25519 signature, hex encoded.
        public_key: The raw Ed25519 public key, hex encoded.

    Returns:
        A JSON-ready document. Every field a verifier needs is present, so the
        recipient depends on nothing held by the operator.
    """
    return {
        "format": FORMAT,
        "checkpoint_id": checkpoint_id,
        "tree_size": tree_size,
        "root": root,
        "signed_at": signed_at.isoformat(),
        "signature": signature,
        "public_key": public_key,
    }


def _filename(checkpoint_id: str, signed_at: datetime.datetime, tree_size: int) -> str:
    """Name a checkpoint file so a directory of them sorts and reads sensibly."""
    stamp = signed_at.strftime("%Y%m%dT%H%M%SZ")
    safe = "".join(character if character.isalnum() else "-" for character in checkpoint_id)
    return f"{safe}-{stamp}-size{tree_size}.json"


def main(argv: Sequence[str] | None = None) -> int:
    """Sign the log's current state and write it out for transfer.

    Args:
        argv: Command line arguments, for testing. Defaults to `sys.argv`.

    Returns:
        A process exit code: 0 if a checkpoint was written, `REFUSED` if not.
    """
    parser = argparse.ArgumentParser(
        prog="python -m api.publish_checkpoint",
        description="Write a signed checkpoint to a file, for transfer off this machine.",
    )
    parser.add_argument(
        "--out",
        default=".",
        help="Directory to write the checkpoint into. Created if absent.",
    )
    arguments = parser.parse_args(argv)

    try:
        settings = from_environment()
    except ConfigurationError as error:
        print(f"Refused: {error}", file=sys.stderr)
        return REFUSED

    key: Ed25519PrivateKey | None = settings.ledger_key
    if key is None:
        print(
            "Refused: this checkpoint holds no signing key, so nothing can be "
            f"published. Set {LEDGER_KEY_FILE} to the Ed25519 private key file. "
            "No unsigned substitute is written, because one would look like proof.",
            file=sys.stderr,
        )
        return REFUSED

    factory = create_session_factory(settings.database_url)
    with factory() as session:
        log = load_log(session)
        signed = log.checkpoint(key=key, signed_at=datetime.datetime.now(tz=datetime.UTC))

    public = key.public_key()
    if not verify_checkpoint(signed, key=public):  # pragma: no cover - just signed
        print("Refused: the signed checkpoint did not verify against its own key.", file=sys.stderr)
        return REFUSED

    document = checkpoint_document(
        checkpoint_id=settings.checkpoint_id,
        tree_size=signed.tree_size,
        root=signed.root.hex(),
        signed_at=signed.signed_at,
        signature=signed.signature.hex(),
        public_key=public.public_bytes_raw().hex(),
    )

    folder = pathlib.Path(arguments.out)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / _filename(settings.checkpoint_id, signed.signed_at, signed.tree_size)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {path}")
    print(f"  {signed.tree_size} entries, root {signed.root.hex()}")
    if signed.tree_size == 0:
        print("  The log is empty. This still proves that it was empty at this time.")
    print(
        "\nThis proves nothing while it stays on this machine. Send it to somebody "
        "outside this deployment, and keep every one you send."
    )
    print("A recipient checks it with:  python tools/verify_checkpoint.py " + str(path))
    return 0


if __name__ == "__main__":  # pragma: no cover - the process entry point
    raise SystemExit(main())
