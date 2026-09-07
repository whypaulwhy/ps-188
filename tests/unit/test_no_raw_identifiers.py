"""The rule 3 guard: no raw document number reaches storage.

Three separate checks, because the rule can be broken in three separate ways.

1. Nothing committed to this repository is an issuable Aadhaar number.
2. Only the hashing module reads a number in the clear.
3. No contract field can carry one.

**The fourth check lives in `test_persistence.py`.** The roadmap's exit
criterion for phase 3 names a *persistence path*, and there was none to name
until phase 9 built one. It exists now, and the criterion is tested there
against a real database.

Both files ask the same question through the same function,
:func:`core.privacy.identifiers.find_issuable_aadhaar`. That is deliberate: if
the scan and the database guard could disagree about what an issuable number
looks like, one of them would be enforcing a rule nobody had checked.
"""

from __future__ import annotations

import pathlib
from typing import Final

import pytest

from core import contracts
from core.privacy import RawIdentifier, mask_value
from core.privacy.identifiers import find_issuable_aadhaar
from core.standards.verhoeff import verhoeff_digit

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
        # Not committed content, and it carries .json files. Scanning it made
        # the test count depend on whether a tool had run on that machine.
        ".import_linter_cache",
    }
)

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
    found = find_issuable_aadhaar(path.read_text(encoding="utf-8", errors="ignore"))

    assert found is None, (
        f"{path.relative_to(REPO).as_posix()} contains {mask_value(found or '')}, "
        f"which has the shape of an issuable Aadhaar number"
    )


def test_the_scan_would_notice_a_real_number() -> None:
    """A scan that cannot fail is not a guard, so this proves it can.

    The number is computed rather than written down, because writing one into
    this file would make the test above fail on the test below.
    """
    body = "23456789012"

    assert find_issuable_aadhaar(f"reference {body + verhoeff_digit(body)} on file") is not None


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
