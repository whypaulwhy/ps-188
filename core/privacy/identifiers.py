"""A document number in the clear, held so that it cannot leak by accident.

Rule 3 of CLAUDE.md forbids storing an Aadhaar number, and the same applies to
any raw document number. The weakness of that rule as normally implemented is
that a raw number is just a `str`, and a `str` slips into a log line, an
exception message, a JSON body or a database column without anyone deciding
that it should.

:class:`RawIdentifier` closes the accidental paths, leaving one deliberate one:

* `str`, `repr` and f-string interpolation all give the masked form, so a
  number swept into a log or an error message is already masked;
* it has no Pydantic schema, so a contract field of this type **fails at class
  definition**. A raw number cannot enter the evidence contract, and therefore
  cannot reach the ledger or the database through it;
* :meth:`RawIdentifier.reveal` is the single way to obtain the digits, and it
  is named to be greppable. A test asserts that only
  :mod:`core.privacy.hashing` calls it.

What this does not do is make the number safe. It is still in memory, and any
code holding the object can call `reveal`. This is a guard against accident,
not against an attacker who is already running code in the process.

**Normalisation is part of identity.** Spacing, hyphens and case are stripped
on construction, because two renderings of the same number must hash to the
same value. `reveal` returns the normalised digits, not the characters
originally passed in.

**No format validation happens here.** A forged document carries a number that
fails its checksum, and the system has to be able to hold, hash and report that
number. Deciding whether a number is well formed is a Rung 1 detector's job.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Final

from core.privacy.masking import mask_value
from core.standards.verhoeff import verhoeff_is_valid

ISSUABLE_PREFIXES: Final[frozenset[str]] = frozenset("23456789")
"""UIDAI issues no Aadhaar number beginning with 0 or 1."""

TWELVE_DIGITS: Final[re.Pattern[str]] = re.compile(r"(?<!\d)(\d{12})(?!\d)")
"""A twelve-digit run that is not part of a longer number."""

SHA256_TOKEN: Final[re.Pattern[str]] = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
"""A hex digest. Removed before scanning: a digest is not a document number."""

_STRIPPED: Final[str] = " -/"
"""Separators removed on construction. Two spellings of one number must not diverge."""


class IdentifierKind(StrEnum):
    """Which kind of document number this is.

    Used to keep hashes of different document types in separate namespaces, so
    that the same digits appearing as a voter card number and as a driving
    licence number do not produce the same digest and link two records that
    have nothing to do with each other.
    """

    AADHAAR = "AADHAAR"
    PASSPORT = "PASSPORT"
    DRIVING_LICENCE = "DRIVING_LICENCE"
    VOTER_EPIC = "VOTER_EPIC"
    NEPALI_CITIZENSHIP = "NEPALI_CITIZENSHIP"
    NEPALI_NATIONAL_ID = "NEPALI_NATIONAL_ID"
    BHUTANESE_CID = "BHUTANESE_CID"


class RawIdentifier:
    """A document number in the clear, which masks itself everywhere but one method."""

    __slots__ = ("_value", "kind")

    def __init__(self, value: str, *, kind: IdentifierKind) -> None:
        """Hold a raw document number.

        Args:
            value: The number as read from the document. Separators and case
                are normalised away.
            kind: Which kind of document number this is.

        Raises:
            ValueError: If the value is empty once normalised.
        """
        normalised = value.upper()
        for character in _STRIPPED:
            normalised = normalised.replace(character, "")
        if not normalised:
            msg = "a document number cannot be empty"
            raise ValueError(msg)

        self._value = normalised
        self.kind = kind

    def reveal(self) -> str:
        """Return the number in the clear.

        The single deliberate way out of this class, named so that every call
        site can be found with a search. Only :mod:`core.privacy.hashing` may
        call it in production code, and a test enforces that.

        Returns:
            The normalised digits.
        """
        return self._value

    def masked(self) -> str:
        """Return the display form, showing at most the last four characters.

        Returns:
            The masked number, grouped for Aadhaar and plain otherwise.
        """
        if self.kind is IdentifierKind.AADHAAR:
            return mask_value(self._value, group=4)
        return mask_value(self._value)

    def __str__(self) -> str:
        """Return the masked form, so interpolation into a log is already safe."""
        return self.masked()

    def __repr__(self) -> str:
        """Return the masked form, so a traceback or a debugger never shows the digits."""
        return f"RawIdentifier(kind={self.kind.value}, masked={self.masked()!r})"

    def __format__(self, format_spec: str) -> str:
        """Return the masked form, ignoring any format spec.

        f-strings reach `__format__` rather than `__str__`, and a spec such as
        `{number:>20}` would otherwise bypass the masking on some types. It is
        ignored here rather than honoured.
        """
        return self.masked()

    def __eq__(self, other: object) -> bool:
        """Compare two identifiers by kind and value."""
        if not isinstance(other, RawIdentifier):
            return NotImplemented
        return self.kind is other.kind and self._value == other._value

    def __hash__(self) -> int:
        """Hash by kind and value, so identifiers can key an in-memory map."""
        return hash((self.kind, self._value))


def find_issuable_aadhaar(text: str) -> str | None:
    """Return the first number in a text that could be a real Aadhaar number.

    Used in two places that must agree: the test that scans this repository,
    and the guard that stands in front of the database. Sharing one
    implementation means the thing the test checks is the thing the system
    enforces.

    A twelve-digit run counts only if it begins 2 to 9 and satisfies the
    Verhoeff checksum. Hex digests are removed first, because a SHA-256 value
    routinely contains twelve consecutive digits and is not a document number.

    Args:
        text: The text to scan.

    Returns:
        The offending number, or None. Callers must mask it before reporting
        it: a message naming a leaked number has leaked it again.
    """
    for candidate in TWELVE_DIGITS.findall(SHA256_TOKEN.sub("", text)):
        if candidate[0] in ISSUABLE_PREFIXES and verhoeff_is_valid(candidate):
            return str(candidate)
    return None
