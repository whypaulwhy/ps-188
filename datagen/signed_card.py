"""A specimen identity card carrying a signature that actually verifies.

Every other specimen in `datagen` is a document with nothing to check — which is
the honest state of most documents at these borders, and the reason the corpus
looks the way it does. This one is the opposite case: a card an issuing
authority signed, so the path from a photograph to a cryptographic clearance can
be exercised end to end rather than argued about.

**The issuer is fictional and the cryptography is not.** There is no UIDAI
certificate here and none is imitated; the authority is the same invented state
the rest of `datagen` uses. The key is real, the signature is real, and it is
checked by the same `verification.py` a genuine issuer's signature would go
through. What this does not establish is that the system can read anybody
*else's* container — see the note in `detectors/rung0_crypto/signed_qr.py`.

**The private key is returned, never written.** A caller that wants to keep one
must decide to. A generator that quietly left a signing key on disk would be
leaving behind the one thing that can mint documents which clear.
"""

from __future__ import annotations

import base64
import datetime
import io
import json
from dataclasses import dataclass
from typing import Final

import segno
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from PIL import Image, ImageDraw, ImageFont

ISSUING_STATE: Final[str] = "UTOPIA"
"""The same invented state the rest of `datagen` issues documents for."""

ISSUER_ID: Final[str] = "utopia-registry"
"""The anchor name a deployment must install to clear these cards."""

ISSUER_NAME: Final[str] = "Utopia National Registry"

CONTAINER_PREFIX: Final[str] = "SENTINELID-SQR1"
ALGORITHM: Final[str] = "ECDSA_SHA256"
"""P-256 rather than RSA, and the reason is the camera.

An RSA-2048 signature is 256 bytes, which pushes the container past 660
characters and the QR code to version 20 - 105 modules that have to fit on a
card. A P-256 signature is about 70 bytes, so the same card carries a version 13
symbol whose modules are half again as wide. A code a phone cannot read is
reported as unread, so module size is not cosmetic here.
"""

QR_BOX: Final[int] = 420
"""The largest square the code may occupy, so it cannot overrun the card.

The first version of this pasted a 630px symbol onto a 638px card at a negative
offset. It was silently clipped, decoded to nothing, and every card came back
unread - which the system reported honestly and which looked exactly like a
broken detector.
"""

CARD: Final[tuple[int, int]] = (1012, 638)
"""Roughly ID-1 at 300 dpi, which is what a phone photograph of a card yields."""

PAPER: Final[tuple[int, int, int]] = (250, 249, 245)
INK: Final[tuple[int, int, int]] = (18, 18, 20)
QUIET: Final[tuple[int, int, int]] = (95, 95, 100)
BAND: Final[tuple[int, int, int]] = (27, 59, 111)


@dataclass(frozen=True)
class SignedSpecimen:
    """A generated card, the truth about it, and the key that signed it."""

    png: bytes
    """The rendered card."""

    container: bytes
    """The exact bytes encoded into the QR code."""

    payload: dict[str, str]
    """What the issuer signed, as a record."""

    certificate_der: bytes
    """The issuer certificate, for installing as a trust anchor."""

    private_key_pem: bytes
    """The signing key. Returned so a caller must decide to keep it."""

    issuer_id: str = ISSUER_ID


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Return a font bundled with Pillow, so output is the same everywhere."""
    return ImageFont.load_default(size=size)


def issue_certificate(
    key: ec.EllipticCurvePrivateKey, *, not_before: datetime.datetime, years: int = 10
) -> x509.Certificate:
    """Self-sign a certificate for the fictional issuing authority.

    Args:
        key: The authority's key.
        not_before: Start of validity.
        years: How long it is valid for.

    Returns:
        The certificate. Self-signed because this authority is the root of its
        own trust, which is what an operator pins when they install the anchor.
    """
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ISSUER_NAME)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_before.replace(tzinfo=None) + datetime.timedelta(days=365 * years))
        .sign(key, hashes.SHA256())
    )


def build_container(payload: bytes, signature: bytes, *, issuer_id: str = ISSUER_ID) -> bytes:
    """Assemble the wire form of a signed identity code.

    Args:
        payload: The bytes that were signed, exactly.
        signature: The detached signature over them.
        issuer_id: Which authority signed it.

    Returns:
        The container bytes, ready to encode into a QR code.
    """
    chunks = [
        CONTAINER_PREFIX,
        issuer_id,
        ALGORITHM,
        base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    ]
    return "|".join(chunks).encode("ascii")


def _draw_card(container: bytes, payload: dict[str, str]) -> bytes:
    """Render the card, with the container encoded into a QR code on it."""
    card = Image.new("RGB", CARD, PAPER)
    draw = ImageDraw.Draw(card)

    draw.rectangle([(0, 0), (CARD[0] - 1, 96)], fill=BAND)
    draw.text((32, 30), f"GOVERNMENT OF {ISSUING_STATE}", font=_font(34), fill=PAPER)
    draw.text((32, 116), "NATIONAL IDENTITY CARD", font=_font(24), fill=QUIET)

    # A flat panel, not a face. This project does not generate portraits of
    # people who do not exist in order to test a border system.
    draw.rectangle([(40, 165), (250, 445)], fill=(214, 214, 209))
    draw.text((66, 292), "NO PORTRAIT", font=_font(20), fill=QUIET)

    draw.text((300, 175), payload["holder"], font=_font(34), fill=INK)
    draw.text((300, 235), f"Born  {payload['date_of_birth']}", font=_font(24), fill=INK)
    draw.text((300, 275), f"Sex   {payload['sex']}", font=_font(24), fill=INK)
    draw.text((300, 315), f"Ref   {payload['reference']}", font=_font(24), fill=INK)
    draw.text((300, 355), f"Issued  {payload['issued']}", font=_font(24), fill=INK)

    draw.text(
        (300, 470),
        "This card carries a signed code. Scan it to check.",
        font=_font(20),
        fill=QUIET,
    )

    # Fine print and a guilloche-style ground, across the whole face. A real
    # identity card is densely printed; a sparse mockup is not a cheaper version
    # of one, it is a different image. See the note on ELA in the module
    # docstring for why that distinction turned out to matter.
    _draw_security_ground(draw)

    # Error correction M, and a wide quiet zone: a phone photograph of a card is
    # not a clean scan, and a code that cannot be read is reported as unread.
    code = segno.make(container.decode("ascii"), error="m")
    border = 4
    modules = code.symbol_size(scale=1, border=border)[0]
    # Chosen from the symbol rather than assumed. A fixed scale silently clips
    # the moment the payload grows by one version.
    scale = max(1, QR_BOX // modules)
    buffer = io.BytesIO()
    code.save(buffer, kind="png", scale=scale, border=border)
    symbol = Image.open(buffer).convert("RGB")
    if symbol.width > CARD[0] or symbol.height > CARD[1]:  # pragma: no cover - guarded above
        msg = f"the code is {symbol.size} and does not fit on a {CARD} card"
        raise ValueError(msg)
    card.paste(symbol, (CARD[0] - symbol.width - 36, (CARD[1] - symbol.height) // 2))

    out = io.BytesIO()
    card.save(out, format="PNG")
    return out.getvalue()


def _draw_security_ground(draw: ImageDraw.ImageDraw) -> None:
    """Lay a fine repeating pattern and microprint over the card face.

    Real identity documents carry guilloche, microprint and tint across their
    whole surface. The first version of this card left large areas of flat
    paper, which is not what a camera ever sees at a border.
    """
    tint = (232, 234, 238)
    for x in range(0, CARD[0], 9):
        draw.line([(x, 100), (x - 120, CARD[1])], fill=tint, width=1)
    for y in range(104, CARD[1], 11):
        draw.line([(0, y), (CARD[0], y)], fill=tint, width=1)

    micro = _font(9)
    line = (f"{ISSUING_STATE} NATIONAL REGISTRY SPECIMEN " * 6)[:150]
    for y in range(430, CARD[1] - 12, 14):
        draw.text((40, y), line, font=micro, fill=(206, 208, 214))


def generate_signed_card(
    *,
    holder: str = "SPECIMEN TEST CASE",
    date_of_birth: str = "1990-01-01",
    sex: str = "M",
    reference: str = "UTO-SPECIMEN-0001",
    issued: str = "2026-01-01",
    signed_at: datetime.datetime | None = None,
    tamper_after_signing: bool = False,
) -> SignedSpecimen:
    """Generate a specimen card whose issuer signature verifies.

    Args:
        holder: The name printed and signed.
        date_of_birth: As printed and signed.
        sex: As printed and signed.
        reference: The card's own reference. Not a document number of any real
            scheme, and deliberately not twelve digits.
        issued: The issue date.
        signed_at: When the certificate becomes valid. Defaults to a year ago,
            so a card generated now is inside its anchor's window.
        tamper_after_signing: Edit the payload after signing it, keeping the
            original signature. Produces a card that must come back
            `PROOF_INVALID` — the case the whole rung exists to catch.

    Returns:
        The card, the container, the certificate and the signing key.
    """
    moment = signed_at or (datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(days=365))
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = issue_certificate(key, not_before=moment)

    record = {
        "issuer": ISSUER_NAME,
        "document": f"{ISSUING_STATE} NATIONAL IDENTITY CARD",
        "holder": holder,
        "date_of_birth": date_of_birth,
        "sex": sex,
        "reference": reference,
        "issued": issued,
    }
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))

    printed = dict(record)
    if tamper_after_signing:
        # The signature still covers the original bytes. Both the printed card
        # and the container now say something the issuer never signed.
        printed["holder"] = "SOMEBODY ELSE ENTIRELY"
        altered = json.dumps(printed, separators=(",", ":"), sort_keys=True).encode("utf-8")
        container = build_container(altered, signature)
    else:
        container = build_container(payload, signature)

    return SignedSpecimen(
        png=_draw_card(container, printed),
        container=container,
        payload=printed,
        certificate_der=certificate.public_bytes(serialization.Encoding.DER),
        private_key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
