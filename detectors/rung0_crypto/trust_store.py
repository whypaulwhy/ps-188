"""The issuer keys a Rung 0 detector is allowed to trust.

This is the highest-value target in the system. An attacker who can add an
anchor here can mint documents that clear, which is the only path to a forged
clearance — see `docs/threat-model.md`.

Two consequences shape the design.

**Anchors are passed in, never loaded.** A detector receives a `TrustStore` it
did not build, from a caller that got it from reviewed configuration. Rule 5 of
CLAUDE.md requires it, and it also means a detector cannot widen its own trust.

**An anchor carries its own limits.** Each one states which signature
algorithms it may be used with and the window in which it is valid. A signature
that verifies against an expired anchor, or with an algorithm the anchor does
not permit, does not clear the document. Both are refusals to answer, not
findings of forgery.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


class SignatureAlgorithm(StrEnum):
    """A signature algorithm an anchor may be used with.

    Deliberately a short allowlist. SHA-1 constructions and RSA keys below 2048
    bits have no member here and therefore cannot be selected, rather than
    being permitted and discouraged.
    """

    ED25519 = "ED25519"
    RSA_PKCS1V15_SHA256 = "RSA_PKCS1V15_SHA256"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"
    ECDSA_SHA256 = "ECDSA_SHA256"


MINIMUM_RSA_KEY_BITS: Final[int] = 2048
"""RSA keys shorter than this are refused, whatever an anchor claims to permit."""


@dataclass(frozen=True)
class TrustAnchor:
    """One issuer key this deployment is willing to trust, and its limits."""

    issuer_id: str
    """Stable identifier for the issuer, used to select an anchor and to audit a decision."""

    public_key: PublicKeyTypes
    """The verifying key."""

    permitted_algorithms: frozenset[SignatureAlgorithm]
    """Algorithms this anchor may be used with. An empty set trusts nothing."""

    not_before: datetime.datetime
    """Start of the anchor's validity. Must carry a timezone."""

    not_after: datetime.datetime
    """End of the anchor's validity. Must carry a timezone."""

    certificate_der: bytes | None = None
    """The issuer certificate, when the format needs one (XMLDSig, CMS)."""

    def __post_init__(self) -> None:
        """Reject an anchor that cannot be reasoned about.

        Raises:
            ValueError: If the identifier is empty, the timestamps are naive,
                or the validity window is inverted.
        """
        if not self.issuer_id.strip():
            msg = "an anchor must name its issuer"
            raise ValueError(msg)
        for label, moment in (("not_before", self.not_before), ("not_after", self.not_after)):
            if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
                msg = f"{label} must be timezone aware"
                raise ValueError(msg)
        if self.not_after <= self.not_before:
            msg = "an anchor's validity window must be non-empty"
            raise ValueError(msg)

    def is_valid_at(self, when: datetime.datetime) -> bool:
        """Report whether this anchor may be used at a given instant.

        Args:
            when: The instant to judge against, normally the time of the
                crossing rather than now, so a case replays identically.

        Returns:
            Whether the instant falls inside the validity window.
        """
        return self.not_before <= when <= self.not_after

    def permits(self, algorithm: SignatureAlgorithm) -> bool:
        """Report whether this anchor may be used with a given algorithm.

        Args:
            algorithm: The algorithm the signature claims to use.

        Returns:
            Whether the anchor permits it.
        """
        return algorithm in self.permitted_algorithms


class TrustStore:
    """The set of issuer anchors a screening may rely on.

    Immutable once constructed. Empty is a legitimate state and means no
    document can be cleared cryptographically — which is the correct behaviour
    for a deployment that has not yet been provisioned with real issuer keys,
    and is what every case will say out loud.
    """

    __slots__ = ("_anchors",)

    def __init__(self, anchors: Sequence[TrustAnchor] = ()) -> None:
        """Hold a set of anchors.

        Args:
            anchors: The anchors to trust.

        Raises:
            ValueError: If two anchors claim the same issuer identifier, which
                would make selection arbitrary.
        """
        identifiers = [anchor.issuer_id for anchor in anchors]
        if len(identifiers) != len(set(identifiers)):
            msg = "two anchors cannot claim the same issuer_id"
            raise ValueError(msg)
        self._anchors = tuple(anchors)

    def anchor(self, issuer_id: str) -> TrustAnchor | None:
        """Return the anchor for an issuer, or None if this deployment has none.

        Args:
            issuer_id: The issuer to look up.

        Returns:
            The anchor, or None. None means the document cannot be checked, not
            that it is false.
        """
        for anchor in self._anchors:
            if anchor.issuer_id == issuer_id:
                return anchor
        return None

    def certificates(self) -> tuple[bytes, ...]:
        """Return every anchor certificate, for formats that validate a chain.

        Returns:
            The DER encodings, in anchor order, skipping anchors that carry a
            bare key rather than a certificate.
        """
        return tuple(
            anchor.certificate_der for anchor in self._anchors if anchor.certificate_der is not None
        )

    def __len__(self) -> int:
        """Return how many anchors this store holds."""
        return len(self._anchors)

    def __iter__(self) -> Iterator[TrustAnchor]:
        """Iterate the anchors in the order they were given."""
        return iter(self._anchors)
