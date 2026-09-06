"""The rule 3 guard: no raw document number reaches storage.

Three separate checks, because the rule can be broken in three separate ways.

1. Nothing committed to this repository is an issuable Aadhaar number.
2. Only the hashing module reads a number in the clear.
3. No contract field can carry one.

**What this does not yet cover.** The roadmap's exit criterion for phase 3 is a
test that fails if a raw number can reach any *persistence path*. There is no
persistence path — `db/` is stubs until phase 9 — so the strongest available
statement today is the three above. The database test lands in phase 9 against
real persistence, and the roadmap says so rather than treating this as
finished.
"""

from __future__ import annotations

import pathlib
import re
from typing import Final

import pytest

from core import contracts
from core.privacy import RawIdentifier, mask_value
from core.standards.verhoeff import verhoeff_is_valid

REPO: Final[pathlib.Path] = pathlib.Path(__file__).parents[2]

SCANNED_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".py", ".md", ".json", ".toml", ".cfg", ".txt", ".yml", ".yaml", ".ini"}
)
"""Text formats a number could realistically be committed into."""

SKIPPED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".hypothesis",
        "htmlcov",
    }
)

TWELVE_DIGITS: Final[re.Pattern[str]] = re.compile(r"(?<!\d)(\d{12})(?!\d)")
"""A twelve-digit run that is not part of a longer number."""

SHA256_TOKEN: Final[re.Pattern[str]] = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
"""A hex digest. Removed before scanning, since a digest is not a document number."""

NOT_ISSUABLE_PREFIXES: Final[frozenset[str]] = frozenset("01")
"""UIDAI issues no Aadhaar number beginning with 0 or 1, which is why fixtures start with 0."""

REVEAL_IS_ALLOWED_IN: Final[frozenset[str]] = frozenset(
    {
        "core/privacy/identifiers.py",
        "core/privacy/hashing.py",
    }
)
"""The only production modules permitted to read a number in the clear."""


def source_files() -> list[pathlib.Path]:
    """Return every committed text file worth scanning."""
    found: list[pathlib.Path] = []
    for path in REPO.rglob("*"):
        if not path.is_file() or path.suffix not in SCANNED_SUFFIXES:
            continue
        if SKIPPED_DIRECTORIES & set(path.relative_to(REPO).parts):
            continue
        found.append(path)
    return sorted(found)


FILES: Final[list[pathlib.Path]] = source_files()


def test_the_scan_actually_covers_the_repository() -> None:
    """A discovery bug that found nothing would make the guard below vacuous."""
    names = {path.relative_to(REPO).as_posix() for path in FILES}

    assert len(FILES) > 60
    assert "core/privacy/hashing.py" in names
    assert "tests/golden/vectors/verhoeff.json" in names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(REPO).as_posix())
def test_no_file_contains_an_issuable_aadhaar_number(path: pathlib.Path) -> None:
    """Nothing in this repository is a number that could belong to a real person.

    A twelve-digit run counts as one only if it starts 2 to 9 and satisfies the
    Verhoeff checksum. The phase-1 fixtures start with 0 deliberately, so they
    exercise the arithmetic without any of them being issuable.

    The failure message masks what it found. A test that reports a leaked
    number in a CI log has leaked it again.
    """
    text = SHA256_TOKEN.sub("", path.read_text(encoding="utf-8", errors="ignore"))

    for candidate in TWELVE_DIGITS.findall(text):
        issuable = candidate[0] not in NOT_ISSUABLE_PREFIXES and verhoeff_is_valid(candidate)
        assert not issuable, (
            f"{path.relative_to(REPO).as_posix()} contains {mask_value(candidate)}, "
            f"which has the shape of an issuable Aadhaar number"
        )


def test_only_the_hashing_module_reads_a_number_in_the_clear() -> None:
    """`reveal` is the one deliberate way out, so its call sites are enumerated.

    Test code may call it; production code may not, except where the value has
    to be turned into a digest.
    """
    offenders = [
        path.relative_to(REPO).as_posix()
        for path in FILES
        if path.suffix == ".py"
        and not path.relative_to(REPO).as_posix().startswith("tests/")
        and ".reveal()" in path.read_text(encoding="utf-8", errors="ignore")
    ]

    assert set(offenders) <= REVEAL_IS_ALLOWED_IN, (
        f"{sorted(set(offenders) - REVEAL_IS_ALLOWED_IN)} read a document number in the clear"
    )


def test_no_contract_field_can_carry_a_raw_identifier() -> None:
    """The evidence contract is what reaches the ledger and the database.

    Pydantic has no schema for `RawIdentifier`, so such a field fails at class
    definition rather than at serialisation. This walks the contracts anyway,
    so that the guarantee is checked rather than assumed.
    """
    models = [
        contracts.Evidence,
        contracts.Finding,
        contracts.Provenance,
        contracts.Subject,
        contracts.Verdict,
        contracts.Artefact,
        contracts.DecodedCode,
        contracts.TextZone,
    ]

    for model in models:
        for name, field in model.model_fields.items():
            assert field.annotation is not RawIdentifier, f"{model.__name__}.{name}"
