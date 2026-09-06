"""The skeleton has to be importable, and its stubs have to be honest.

Two things are checked. First, that every module in the tree imports cleanly,
which is what makes the phase-0 layout worth anything. Second, that every stub
raises ``NotImplementedError`` rather than quietly returning a placeholder
value: a stub that returns ``None`` or ``0.0`` is how fabricated results get
into a system.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from types import ModuleType

import pytest

ROOT_PACKAGES: tuple[str, ...] = (
    "api",
    "core",
    "datagen",
    "db",
    "detectors",
    "eval",
    "explain",
    "extraction",
    "ledger",
    "ui",
)
"""Every top-level package in the repository."""

IMPLEMENTED: frozenset[str] = frozenset(
    {
        "core.contracts",
        "core.contracts.enums",
        "core.contracts.evidence",
        "core.contracts.finding",
        "core.contracts.provenance",
        "core.contracts.subject",
        "core.contracts.verdict",
        "core.privacy",
        "core.privacy.hashing",
        "core.privacy.identifiers",
        "core.privacy.masking",
        "core.privacy.retention",
        "core.standards.date_rules",
        "core.standards.errors",
        "core.standards.mrz.check_digits",
        "core.standards.mrz.parse",
        "core.standards.verhoeff",
        "core.trust",
        "core.trust.ladder",
        "core.trust.policy",
        "detectors",
        "detectors.base",
        "detectors.rung0_crypto.digilocker_xml_sig",
        "detectors.rung0_crypto.pdf_pkcs7",
        "detectors.rung0_crypto.trust_store",
        "detectors.rung0_crypto.verification",
    }
)
"""The modules phase 0 implements for real. Everything else must still be a stub."""


def _discover() -> list[str]:
    """Return the dotted name of every module in the tree, roots included."""
    names: list[str] = []
    for root in ROOT_PACKAGES:
        package = importlib.import_module(root)
        names.append(root)
        names.extend(info.name for info in pkgutil.walk_packages(package.__path__, f"{root}."))
    return sorted(names)


MODULES: list[str] = _discover()


def test_the_tree_is_not_empty() -> None:
    """A discovery bug that found nothing would make every test below vacuous."""
    assert len(MODULES) > 50


@pytest.mark.parametrize("name", MODULES)
def test_every_module_imports(name: str) -> None:
    """Nothing in the skeleton is broken on import."""
    assert isinstance(importlib.import_module(name), ModuleType)


@pytest.mark.parametrize("name", [name for name in MODULES if name not in IMPLEMENTED])
def test_unimplemented_modules_refuse_to_pretend(name: str) -> None:
    """Every callable in a stub module raises instead of returning a placeholder.

    Package markers hold no callables and pass trivially. Anything else must
    fail loudly when called, so an unimplemented check can never be mistaken
    for a check that found nothing wrong.
    """
    module = importlib.import_module(name)

    for _, member in inspect.getmembers(module, inspect.isfunction):
        if member.__module__ != name:
            continue
        source = inspect.getsource(member)
        assert "NotImplementedError" in source, f"{name}.{member.__name__} does not raise"
