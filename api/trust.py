"""Reading this deployment's trust anchors from configuration.

`detectors/rung0_crypto/trust_store.py` calls the trust store the highest-value
target in the system, and it is right: an attacker who can add an anchor can
mint documents that clear. Until now there was no way to add one at all, so no
document could ever be cleared and the only rung that can say "genuine" was
inert. That is safe, and it is also half a system.

This module is the other half, and it is deliberately narrow.

**An anchor is a file an operator put there on purpose.** The path comes from
`SENTINELID_TRUST_ANCHORS_FILE`; nothing is discovered, downloaded or inferred.
There is no fallback to the operating system's certificate store: those roots
exist to authenticate web servers, and inheriting them would mean this system
trusted several hundred commercial authorities to attest to identity documents.

**The permitted algorithms are stated, never derived.** A certificate does not
say which algorithms it may be used with; it merely contains a key that several
would accept. Deriving the set would silently widen trust every time a key type
gained a new construction, so the file has to name them.

**The validity window comes from the certificate, and may only be narrowed.**
An operator who wants to stop trusting an issuer before its certificate expires
can say so. One who tries to extend trust past the certificate's own expiry is
refused: that is not configuration, it is overriding the issuer.
"""

from __future__ import annotations

import datetime
import json
import pathlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding

from detectors.rung0_crypto.trust_store import (
    SignatureAlgorithm,
    TrustAnchor,
    TrustStore,
)


class TrustConfigurationError(RuntimeError):
    """The trust anchors could not be read, so the deployment must not start.

    Refused rather than degraded. A deployment that silently started with fewer
    anchors than its operator configured would refuse genuine documents, and a
    deployment that started with more would clear forged ones. Neither is
    something to discover from a log line.
    """


def _certificate_bytes(path: pathlib.Path) -> bytes:
    """Read a certificate file, whatever the operator's tooling produced."""
    try:
        return path.read_bytes()
    except OSError as error:
        msg = f"cannot read the certificate at {path}: {error}"
        raise TrustConfigurationError(msg) from error


def load_certificate(path: pathlib.Path) -> x509.Certificate:
    """Load one X.509 certificate, in PEM or DER form.

    Both are accepted because both are what an issuer actually hands out: a
    `.cer` from a Windows export is DER, a `.pem` from anything else is base64.
    Requiring one would mean an operator converting a file at a checkpoint.

    Args:
        path: The certificate file.

    Returns:
        The parsed certificate.

    Raises:
        TrustConfigurationError: If the file cannot be read or is not a
            certificate in either encoding.
    """
    raw = _certificate_bytes(path)
    try:
        return x509.load_pem_x509_certificate(raw)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(raw)
    except ValueError as error:
        msg = f"{path} is not an X.509 certificate in PEM or DER form"
        raise TrustConfigurationError(msg) from error


def _algorithms(entry: dict[str, Any], *, issuer_id: str) -> frozenset[SignatureAlgorithm]:
    """Read the algorithms an anchor may be used with. Never inferred."""
    named = entry.get("permitted_algorithms")
    if not isinstance(named, list) or not named:
        msg = (
            f"anchor {issuer_id!r} must list permitted_algorithms. "
            f"They are not derived from the certificate, because that would widen "
            f"trust whenever a key type gained a new construction."
        )
        raise TrustConfigurationError(msg)

    chosen: set[SignatureAlgorithm] = set()
    for name in named:
        try:
            chosen.add(SignatureAlgorithm(name))
        except ValueError as error:
            permitted = ", ".join(sorted(item.value for item in SignatureAlgorithm))
            msg = f"anchor {issuer_id!r} names unknown algorithm {name!r}. Choose from: {permitted}"
            raise TrustConfigurationError(msg) from error
    return frozenset(chosen)


def _window(
    entry: dict[str, Any], certificate: x509.Certificate, *, issuer_id: str
) -> tuple[datetime.datetime, datetime.datetime]:
    """Return the anchor's validity window, narrowed by configuration if asked."""
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    for label, bound in (("not_before", not_before), ("not_after", not_after)):
        stated = entry.get(label)
        if stated is None:
            continue
        try:
            moment = datetime.datetime.fromisoformat(str(stated))
        except ValueError as error:
            msg = f"anchor {issuer_id!r} has an unreadable {label}: {stated!r}"
            raise TrustConfigurationError(msg) from error
        if moment.tzinfo is None:
            msg = f"anchor {issuer_id!r} {label} must carry a timezone"
            raise TrustConfigurationError(msg)
        widens = moment < bound if label == "not_before" else moment > bound
        if widens:
            msg = (
                f"anchor {issuer_id!r} {label} would extend trust beyond the "
                f"certificate's own validity ({bound.isoformat()}). An anchor may "
                f"be narrowed by configuration, never widened."
            )
            raise TrustConfigurationError(msg)
        if label == "not_before":
            not_before = moment
        else:
            not_after = moment

    if not_after <= not_before:
        msg = f"anchor {issuer_id!r} has an empty validity window"
        raise TrustConfigurationError(msg)
    return not_before, not_after


def _anchor(entry: dict[str, Any], *, relative_to: pathlib.Path) -> TrustAnchor:
    """Build one anchor from one entry in the configuration file."""
    issuer_id = str(entry.get("issuer_id") or "").strip()
    if not issuer_id:
        msg = "every trust anchor must name its issuer with issuer_id"
        raise TrustConfigurationError(msg)

    named_path = entry.get("certificate")
    if not named_path:
        msg = f"anchor {issuer_id!r} must name a certificate file"
        raise TrustConfigurationError(msg)

    path = pathlib.Path(str(named_path))
    if not path.is_absolute():
        path = relative_to / path

    certificate = load_certificate(path)
    not_before, not_after = _window(entry, certificate, issuer_id=issuer_id)
    public_key: PublicKeyTypes = certificate.public_key()

    return TrustAnchor(
        issuer_id=issuer_id,
        public_key=public_key,
        permitted_algorithms=_algorithms(entry, issuer_id=issuer_id),
        not_before=not_before,
        not_after=not_after,
        certificate_der=certificate.public_bytes(Encoding.DER),
    )


def read_trust_anchors(path: pathlib.Path) -> TrustStore:
    """Read the deployment's trust anchors from a JSON file.

    The file is a list of objects, each naming an issuer, a certificate file
    beside it, and the algorithms that anchor may be used with:

        [
          {
            "issuer_id": "digilocker",
            "certificate": "digilocker.cer",
            "permitted_algorithms": ["RSA_PKCS1V15_SHA256"]
          }
        ]

    A relative certificate path is resolved against the directory holding this
    file, so an anchors directory can be moved or mounted as a unit.

    Args:
        path: The anchors file.

    Returns:
        The trust store. An empty list is valid and means this deployment
        clears nothing cryptographically, which every case then states.

    Raises:
        TrustConfigurationError: If the file cannot be read, is not the
            expected shape, names an unknown algorithm, points at something
            that is not a certificate, or tries to widen an anchor's validity.
    """
    try:
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as error:
        msg = f"cannot read the trust anchors at {path}: {error}"
        raise TrustConfigurationError(msg) from error
    except json.JSONDecodeError as error:
        msg = f"the trust anchors at {path} are not valid JSON: {error}"
        raise TrustConfigurationError(msg) from error

    if not isinstance(loaded, list):
        msg = f"the trust anchors at {path} must be a JSON list of anchors"
        raise TrustConfigurationError(msg)

    folder = path.parent
    anchors = [_anchor(entry, relative_to=folder) for entry in _objects(loaded, path=path)]
    try:
        return TrustStore(anchors)
    except ValueError as error:
        msg = f"the trust anchors at {path} are not usable: {error}"
        raise TrustConfigurationError(msg) from error


def _objects(loaded: list[Any], *, path: pathlib.Path) -> list[dict[str, Any]]:
    """Reject anything in the list that is not an anchor object."""
    entries: list[dict[str, Any]] = []
    for item in loaded:
        if not isinstance(item, dict):
            msg = f"every entry in {path} must be an object describing one anchor"
            raise TrustConfigurationError(msg)
        entries.append(item)
    return entries
