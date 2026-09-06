"""Tests of the detector base class and registry.

Phase 0 ships no detectors, so these tests build throwaway ones. What is being
checked is that the registry refuses anything that would weaken the audit trail:
an unregisterable class, a malformed identifier, or two detectors claiming the
same name.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator

import pytest

from core.contracts import Evidence, Result, Rung, Subject
from detectors import Detector, clear_registry, get, register, registered
from tests.support import DIGEST, subject


@pytest.fixture(autouse=True)
def _empty_registry() -> Iterator[None]:
    """Give every test a clean registry and leave nothing behind."""
    clear_registry()
    yield
    clear_registry()


class _Stub(Detector):
    """A minimal detector used only to exercise the registry."""

    id = "test.stub"
    rung = Rung.DETERMINISTIC

    def applies_to(self, document: Subject) -> bool:
        """Apply to everything."""
        return True

    def run(self, document: Subject) -> tuple[Evidence, ...]:
        """Report a passing deterministic check."""
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=Result.PASS,
                reasons=("Nothing to report.",),
                standard_ref="ICAO Doc 9303 Part 3 s.4.2.2",
                runtime_ms=0.1,
                model_version="stub/1",
                input_digest=DIGEST,
            ),
        )


def test_a_detector_cannot_be_instantiated_without_both_methods() -> None:
    """The abstract base refuses a partial implementation."""

    class Partial(Detector):
        id = "test.partial"
        rung = Rung.DETERMINISTIC

        def applies_to(self, document: Subject) -> bool:
            return True

    with pytest.raises(TypeError):
        Partial()  # type: ignore[abstract]


def test_registering_returns_the_class_unchanged() -> None:
    """The decorator is transparent, so a registered class behaves normally."""
    assert register(_Stub) is _Stub
    assert get("test.stub") is _Stub


def test_a_detector_returns_evidence_not_a_bool() -> None:
    """The contract is evidence in, evidence out. No bare values anywhere."""
    (item,) = _Stub().run(subject())

    assert isinstance(item, Evidence)
    assert item.rung is Rung.DETERMINISTIC


def test_registering_a_non_detector_is_refused() -> None:
    """Only detectors go in the registry."""
    with pytest.raises(TypeError, match="only Detector subclasses"):
        register(str)  # type: ignore[arg-type]


def test_a_detector_must_declare_a_string_id() -> None:
    """An identifier that is not a string cannot key an audit record."""

    class NoId(_Stub):
        id = None  # type: ignore[assignment]

    with pytest.raises(TypeError, match="must declare a string id"):
        register(NoId)


def test_a_detector_must_declare_a_rung() -> None:
    """A detector with no declared rung has no defined authority."""

    class NoRung(_Stub):
        id = "test.norung"
        rung = 1  # type: ignore[assignment]

    with pytest.raises(TypeError, match="must declare a Rung"):
        register(NoRung)


def test_a_malformed_identifier_is_refused() -> None:
    """Identifiers follow the same shape the evidence contract enforces."""

    class BadId(_Stub):
        id = "Test.Stub"

    with pytest.raises(ValueError, match="dotted lowercase identifier"):
        register(BadId)


def test_two_detectors_cannot_claim_the_same_identifier() -> None:
    """A duplicate name would make the audit trail ambiguous."""

    class Clash(_Stub):
        pass

    register(_Stub)

    with pytest.raises(ValueError, match="already registered"):
        register(Clash)


def test_the_registry_is_ordered_by_authority() -> None:
    """Screening runs in a fixed order, most authoritative rung first."""

    class Inference(_Stub):
        id = "test.inference"
        rung = Rung.INFERENCE

    class Crypto(_Stub):
        id = "test.crypto"
        rung = Rung.CRYPTOGRAPHIC

    register(Inference)
    register(Crypto)
    register(_Stub)

    assert [detector.id for detector in registered()] == [
        "test.crypto",
        "test.stub",
        "test.inference",
    ]


def test_an_unknown_identifier_raises() -> None:
    """Asking for a detector that does not exist fails loudly."""
    with pytest.raises(KeyError):
        get("test.nothing")


def test_phase_zero_registers_no_detectors() -> None:
    """Phase 0 is skeleton and contracts. Importing the tree must not register a check.

    If this ever fails, a detector was written ahead of the roadmap, or a stub
    started registering itself before it had an implementation behind it.
    """
    clear_registry()
    for module in (
        "detectors.rung0_crypto.aadhaar_secure_qr",
        "detectors.rung1_deterministic.mrz_checkdigits",
        "detectors.rung2_inference.tamper_classical",
        "detectors.rung3_context.watchlist",
    ):
        importlib.import_module(module)

    assert registered() == ()
