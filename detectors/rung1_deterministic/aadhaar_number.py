"""Rung 1 detector: could the number printed on this card have been issued?

An Aadhaar number is not twelve arbitrary digits. The last digit is derived
from the other eleven by the Verhoeff scheme, so most numbers a person could
invent are not numbers UIDAI could ever have issued. That is arithmetic, not
inference, which is what puts this on Rung 1 — and Rung 1 can reject.

**What a pass means, and what it does not.** A number that satisfies the scheme
is *well formed*. It is emphatically not proof that the number was issued, that
it belongs to the person holding the card, or that the card is genuine. Only the
signature in the Secure QR can say any of that, and that is Rung 0. The officer
wording says so explicitly, because "the number checked out" is exactly the kind
of sentence that gets over-read.

**The risk this detector carries, stated rather than buried.** The number is
read by general text recognition from a photograph. If the recognition misreads
one digit, a genuine card fails the arithmetic and a real person is turned back
— the first-order harm named in `docs/threat-model.md`. Three things hold that
down:

1. it judges only a document *declared* to be an Aadhaar card, so a stray
   twelve-digit run on some other document is never treated as one;
2. it judges only when the printed page was read completely, and reports
   `NOT_APPLICABLE` otherwise rather than guessing;
3. if several candidate numbers are found and **any** of them is well formed,
   that is taken as the number, because the other candidates are recognition
   noise rather than evidence of forgery.

It is still possible for a bad photograph to fail a genuine card. The officer is
told, in the reason, that a poor scan can cause this — and an officer can
override a rejection, which is what `docs/adr/0007` exists for.

**No number reaches the evidence.** Rule 3 of `CLAUDE.md` applies inside this
module as much as at the database: what the officer sees is masked to the last
four digits, and the full number never leaves this function.
"""

from __future__ import annotations

import re
import time
from typing import Final

from core.contracts import DocumentType, Evidence, Result, Rung, Subject, ZoneName
from core.privacy.identifiers import ISSUABLE_PREFIXES, SHA256_TOKEN
from core.privacy.masking import mask_aadhaar
from core.standards.verhoeff import verhoeff_is_valid
from detectors.base import Detector, register

DETECTOR_VERSION: Final[str] = "aadhaar_number/1.0.0"
STANDARD_REF: Final[str] = (
    "UIDAI Aadhaar numbering scheme: twelve digits, the last derived from the "
    "other eleven by the Verhoeff scheme"
)

GROUPED: Final[re.Pattern[str]] = re.compile(r"(?<!\d)(\d{4})[\s\-]?(\d{4})[\s\-]?(\d{4})(?!\d)")
"""Matches an Aadhaar number printed as `1234 5678 9012` or unspaced.

The lookarounds stop a longer digit run being sliced into a false candidate: a
sixteen-digit sequence is not an Aadhaar number with four spare digits.
"""

NOT_DECLARED_AADHAAR: Final[str] = (
    "This document was not presented as an Aadhaar card, so the twelve-digit "
    "Aadhaar number rule was not applied to it. Nothing about this document was "
    "confirmed by this check."
)
PAGE_UNREADABLE: Final[str] = (
    "The printed side of this card could not be read in full, so the number on it "
    "was not checked. This is a problem with the photograph, not a sign that the "
    "card is false."
)
NO_NUMBER_FOUND: Final[str] = (
    "No twelve-digit number could be read from this card, so there was nothing to "
    "check. Photograph the front of the card, flat and in focus, and try again."
)


def candidates(lines: tuple[str, ...]) -> list[str]:
    """Return every twelve-digit sequence on the page that could be an Aadhaar number.

    Args:
        lines: The printed lines as recognition read them.

    Returns:
        Candidate numbers, digits only, in the order found. Hexadecimal digests
        are removed first: a SHA-256 value routinely contains twelve consecutive
        digits and is not a document number.
    """
    page = SHA256_TOKEN.sub("", " ".join(lines))
    return ["".join(match.groups()) for match in GROUPED.finditer(page)]


def is_well_formed(number: str) -> bool:
    """Report whether a twelve-digit number could have been issued.

    Args:
        number: Twelve digits, no separators.

    Returns:
        Whether it begins 2 to 9 and satisfies the Verhoeff scheme. Numbers
        beginning 0 or 1 are not issued, which is why this project's own
        fixtures begin with 0.
    """
    return number[0] in ISSUABLE_PREFIXES and verhoeff_is_valid(number)


@register
class AadhaarNumberDetector(Detector):
    """Checks the arithmetic of the number printed on an Aadhaar card."""

    id = "rung1.aadhaar_number"
    rung = Rung.DETERMINISTIC

    def applies_to(self, subject: Subject) -> bool:
        """Report whether this detector should run. It always should.

        Args:
            subject: The material under examination.

        Returns:
            Always true. A document this check does not apply to is reported as
            not applicable rather than silently skipped, so an officer can tell
            the difference between a number that passed and one nobody read.
        """
        return True

    def run(self, subject: Subject) -> tuple[Evidence, ...]:
        """Judge the printed Aadhaar number, if there is one to judge.

        Args:
            subject: The material under examination.

        Returns:
            One piece of evidence. Never raises.
        """
        started = time.perf_counter()
        result, reasons = self._examine(subject)
        digest = subject.artefacts[0].sha256 if subject.artefacts else subject.provenance.sha256
        return (
            Evidence(
                detector_id=self.id,
                rung=self.rung,
                result=result,
                reasons=reasons,
                standard_ref=STANDARD_REF,
                runtime_ms=(time.perf_counter() - started) * 1000,
                model_version=DETECTOR_VERSION,
                input_digest=digest,
            ),
        )

    def _examine(self, subject: Subject) -> tuple[Result, tuple[str, ...]]:
        """Decide the result and the officer-facing reasons for one document."""
        if subject.declared_type is not DocumentType.AADHAAR:
            return Result.NOT_APPLICABLE, (NOT_DECLARED_AADHAAR,)

        zone = subject.zone(ZoneName.VISUAL_INSPECTION)
        if zone is None or not zone.complete:
            return Result.NOT_APPLICABLE, (PAGE_UNREADABLE,)

        found = candidates(zone.lines)
        if not found:
            return Result.NOT_APPLICABLE, (NO_NUMBER_FOUND,)

        for number in found:
            if is_well_formed(number):
                return Result.PASS, (
                    f"The number printed on this card, {mask_aadhaar(number)}, is built "
                    f"the way an issued Aadhaar number has to be built.",
                    "This does not establish that the number was issued, that it belongs "
                    "to the person presenting it, or that the card is genuine. Only the "
                    "signed code on the card can establish that.",
                )

        return Result.FAIL, (
            f"The number printed on this card, {mask_aadhaar(found[0])}, cannot be an "
            f"Aadhaar number. Every issued number carries a built-in arithmetic pattern, "
            f"and this one does not follow it.",
            "A blurred or angled photograph can also cause this by misreading a digit. "
            "If the card looks genuine, photograph it again flat and in focus before "
            "treating this as a forgery.",
        )


def build() -> Detector:
    """Construct the Aadhaar number detector.

    Returns:
        The detector. It needs nothing passed in: the rule is arithmetic and the
        number comes from the subject.
    """
    return AadhaarNumberDetector()
