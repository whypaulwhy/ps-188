"""Deriving the digest a Rung 3 detector looks up.

Shared by both contextual detectors so that they agree on what identifies a
document. If they disagreed, a watchlist hit and a repeat crossing would be
keyed differently and one of them would silently never match.

The number never leaves this function as a number: it is wrapped in a
`RawIdentifier`, which masks itself everywhere, and handed straight to the
keyed hash. Nothing here reads it in the clear.
"""

from __future__ import annotations

from core.contracts import Subject, ZoneName
from core.privacy import DeploymentKey, IdentifierKind, RawIdentifier, hash_document_number
from core.standards.errors import MrzFormatError
from core.standards.mrz.parse import parse_mrz


def document_digest(subject: Subject, *, key: DeploymentKey) -> str | None:
    """Return the salted digest of the presented document number.

    Args:
        subject: The material under examination.
        key: The deployment key.

    Returns:
        The digest, or None when the document could not be identified at all --
        no strip, an incomplete reading, or a strip that does not parse. None
        means the context could not be checked, which is a different statement
        from finding nothing.
    """
    zone = subject.zone(ZoneName.MRZ)
    if zone is None or not zone.complete:
        return None
    try:
        document = parse_mrz(zone.lines)
    except MrzFormatError:
        return None

    number = document.document_number.rstrip("<")
    if not number:
        return None
    return hash_document_number(RawIdentifier(number, kind=IdentifierKind.PASSPORT), key=key)
