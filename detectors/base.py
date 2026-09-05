"""The contract every check in SENTINEL ID implements, and the registry of them.

A detector is a small, self-contained thing that looks at one subject and
reports :class:`~core.contracts.evidence.Evidence`. It does not decide
anything, does not read the database, does not know what other detectors found,
and does not know what will be done with its answer. That isolation is what
makes the trust ladder trustworthy: a detector cannot lobby.

Two rules are enforced here rather than left to review:

* A detector declares its rung as a class attribute, and the evidence contract
  refuses results the rung is not entitled to. Declaring Rung 0 does not let a
  model produce a proof.
* ``run`` returns evidence even when it fails. A detector that cannot reach its
  model returns ``INCONCLUSIVE`` with a reason an officer can read. It never
  returns nothing and never raises past its own boundary, because a silent
  detector is indistinguishable from a passing one, and CLAUDE.md calls that a
  defect.

.. note::
   The ``subject`` a detector receives is typed as :class:`object` in phase 0.
   The extraction contract that will replace it — the normalised image, the
   located zones, the decoded payloads — is deliberately not invented here; it
   is designed in phase 2 against real captures. Detectors are written from
   phase 4 onwards, by which time the type exists.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar, Final

from core.contracts import Evidence, Rung

DETECTOR_ID: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
"""Dotted lowercase identifier, matching the pattern the evidence contract enforces."""

_REGISTRY: dict[str, type[Detector]] = {}


class Detector(ABC):
    """One check, at one rung, over one subject.

    Subclasses set :attr:`id` and :attr:`rung` as class attributes and
    implement :meth:`applies_to` and :meth:`run`.
    """

    id: ClassVar[str]
    """Stable dotted identifier, unique across the registry. Appears in every audit record."""

    rung: ClassVar[Rung]
    """The trust rung this detector's output sits on. Fixes what it is allowed to report."""

    @abstractmethod
    def applies_to(self, subject: object) -> bool:
        """Report whether this detector has anything to say about a subject.

        A detector that does not apply is skipped and produces no evidence. Use
        this only for genuine inapplicability, such as an MRZ check on a
        document with no machine readable zone. Do not use it to hide a failure:
        if the detector applies but cannot run, implement that in :meth:`run`
        and return an honest inconclusive result.

        Args:
            subject: The material under examination.

        Returns:
            Whether :meth:`run` should be called.
        """

    @abstractmethod
    def run(self, subject: object) -> tuple[Evidence, ...]:
        """Examine a subject and report what was found.

        Args:
            subject: The material under examination.

        Returns:
            Zero or more pieces of evidence, each declaring this detector's
            rung. Returning an empty tuple means the detector genuinely had
            nothing to report; it is not a way to signal failure. Failure is
            reported as evidence with an honest result and a readable reason.
        """


def register(detector: type[Detector]) -> type[Detector]:
    """Add a detector class to the registry, as a decorator.

    Args:
        detector: The detector class to register.

    Returns:
        The same class, unchanged, so the decorator is transparent.

    Raises:
        TypeError: If the class is not a :class:`Detector` subclass, or does not
            declare both ``id`` and ``rung``.
        ValueError: If ``id`` is malformed, or another class already claims it.
    """
    if not (isinstance(detector, type) and issubclass(detector, Detector)):
        msg = "only Detector subclasses can be registered"
        raise TypeError(msg)

    detector_id = getattr(detector, "id", None)
    rung = getattr(detector, "rung", None)
    if not isinstance(detector_id, str):
        msg = f"{detector.__name__} must declare a string id"
        raise TypeError(msg)
    if not isinstance(rung, Rung):
        msg = f"{detector.__name__} must declare a Rung"
        raise TypeError(msg)
    if not DETECTOR_ID.match(detector_id):
        msg = f"{detector_id!r} is not a dotted lowercase identifier"
        raise ValueError(msg)
    if detector_id in _REGISTRY:
        msg = f"{detector_id!r} is already registered by {_REGISTRY[detector_id].__name__}"
        raise ValueError(msg)

    _REGISTRY[detector_id] = detector
    return detector


def get(detector_id: str) -> type[Detector]:
    """Return the registered detector class with a given identifier.

    Args:
        detector_id: The identifier the class was registered under.

    Returns:
        The detector class.

    Raises:
        KeyError: If nothing is registered under that identifier.
    """
    return _REGISTRY[detector_id]


def registered() -> tuple[type[Detector], ...]:
    """Return every registered detector class, ordered by rung then identifier.

    Returns:
        The registered classes, most authoritative rung first. The order is
        stable so that a screening run is reproducible.
    """
    return tuple(sorted(_REGISTRY.values(), key=lambda detector: (detector.rung, detector.id)))


def clear_registry() -> None:
    """Empty the registry.

    Intended for tests, which must not leak registrations into one another.
    """
    _REGISTRY.clear()
