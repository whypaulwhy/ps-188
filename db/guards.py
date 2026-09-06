"""The guard that stands between the system and its own database.

This is the phase-3 exit criterion, which could not be written until there was
a persistence path to guard. Rule 3 of CLAUDE.md forbids storing an Aadhaar
number; phase 3 made that a type error inside the evidence contract, and this
makes it a refusal at the last moment before bytes reach disk.

**Why both.** The contract guard stops a number entering `Evidence`, which is
the route that matters. It does not stop a future developer writing a number
into a plain string column on a new table, in a hurry, at the end of a long
day. This one does, and it does not care where the value came from.

**What it looks for.** A twelve-digit run that begins 2 to 9 and satisfies the
Verhoeff checksum, which is the shape of an issuable Aadhaar number. The same
function backs the test that scans this repository, so the thing the test
checks is exactly the thing the database enforces.

**What it refuses to do is name the number.** A guard that reports the value it
caught has written it into a log, which is the thing it exists to prevent. The
message carries the table and the column, and the number masked.

**What it does not catch.** A number split across two columns, one encoded in
base64, or one written through raw SQL that never becomes a mapped instance.
This closes the ordinary path, not every path; the contract-level guard in
`core/privacy` is what makes the ordinary path the only one worth using.
"""

from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import DeclarativeBase, Session, UOWTransaction, sessionmaker

from core.privacy import mask_value
from core.privacy.identifiers import find_issuable_aadhaar


class RawIdentifierError(ValueError):
    """A write was refused because it would have persisted a document number."""


def _offending_column(instance: DeclarativeBase) -> tuple[str, str, str] | None:
    """Return the table, column and masked value of the first offence found."""
    state = inspect(instance)
    for attribute in state.mapper.column_attrs:
        value = getattr(instance, attribute.key, None)
        if not isinstance(value, str):
            continue
        found = find_issuable_aadhaar(value)
        if found is not None:
            return state.mapper.local_table.name, attribute.key, mask_value(found)
    return None


def refuse_raw_identifiers(session: Session) -> None:
    """Refuse the pending flush if it would write a document number.

    Args:
        session: The session about to flush.

    Raises:
        RawIdentifierError: If any pending row holds a value with the shape of
            an issuable Aadhaar number. The number is masked in the message.
    """
    for instance in (*session.new, *session.dirty):
        if not isinstance(instance, DeclarativeBase):
            continue
        offence = _offending_column(instance)
        if offence is None:
            continue
        table, column, masked = offence
        msg = (
            f"refusing to write {table}.{column}: it contains {masked}, which has "
            f"the shape of an issuable Aadhaar number. Store a keyed digest from "
            f"core.privacy.hashing instead. See rule 3 of CLAUDE.md."
        )
        raise RawIdentifierError(msg)


def install(session_factory: sessionmaker[Session]) -> None:
    """Attach the guard to every session a factory produces.

    Args:
        session_factory: The sessionmaker to guard.
    """

    @event.listens_for(session_factory, "before_flush")
    def _before_flush(session: Session, _context: UOWTransaction, _instances: object) -> None:
        refuse_raw_identifiers(session)
