"""Reading trust anchors, and everything the reader must refuse.

The trust store is the highest-value target in this system: an anchor added
here is a licence to mint documents that clear. So this file is mostly about
refusals, and the two that matter most are `permitted_algorithms` never being
inferred from the certificate, and a validity window never being widened past
what the issuer itself signed.

Certificates are generated here rather than committed. A committed certificate
is a key pair in the repository, and the private half has to exist somewhere for
the fixture to be built at all.
"""

from __future__ import annotations

import datetime
import json
import pathlib
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from api.trust import TrustConfigurationError, load_certificate, read_trust_anchors
from detectors.rung0_crypto.trust_store import SignatureAlgorithm

NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
"""A fixed instant, so the generated certificates are reproducible in effect."""


def make_certificate(
    folder: pathlib.Path,
    *,
    name: str = "issuer.pem",
    not_before: datetime.datetime = NOW,
    not_after: datetime.datetime = NOW + datetime.timedelta(days=365),
    encoding: serialization.Encoding = serialization.Encoding.PEM,
) -> pathlib.Path:
    """Write one self-signed certificate for an imaginary issuer."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Utopia Issuing Authority")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )
    path = folder / name
    path.write_bytes(certificate.public_bytes(encoding))
    return path


def write_anchors(folder: pathlib.Path, entries: list[dict[str, Any]]) -> pathlib.Path:
    """Write an anchors file beside the certificates it names."""
    path = folder / "anchors.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def entry(**overrides: Any) -> dict[str, Any]:  # noqa: ANN401 - arbitrary JSON
    """Build a valid anchor entry, overriding one field at a time."""
    fields: dict[str, Any] = {
        "issuer_id": "utopia",
        "certificate": "issuer.pem",
        "permitted_algorithms": ["RSA_PKCS1V15_SHA256"],
    }
    fields.update(overrides)
    return fields


# The ordinary path


def test_an_anchor_is_read_from_a_certificate(tmp_path: pathlib.Path) -> None:
    """The criterion. Without this, no document can ever be cleared."""
    make_certificate(tmp_path)
    store = read_trust_anchors(write_anchors(tmp_path, [entry()]))

    anchor = store.anchor("utopia")

    assert anchor is not None
    assert anchor.permits(SignatureAlgorithm.RSA_PKCS1V15_SHA256)
    assert anchor.certificate_der is not None


def test_the_window_comes_from_the_certificate(tmp_path: pathlib.Path) -> None:
    """An operator does not retype dates that the issuer already signed."""
    make_certificate(tmp_path)
    store = read_trust_anchors(write_anchors(tmp_path, [entry()]))

    anchor = store.anchor("utopia")

    assert anchor is not None
    assert anchor.is_valid_at(NOW + datetime.timedelta(days=1))
    assert not anchor.is_valid_at(NOW + datetime.timedelta(days=400))


def test_a_der_certificate_is_accepted(tmp_path: pathlib.Path) -> None:
    """A `.cer` exported from Windows is DER. Requiring PEM means converting files."""
    make_certificate(tmp_path, name="issuer.cer", encoding=serialization.Encoding.DER)
    store = read_trust_anchors(write_anchors(tmp_path, [entry(certificate="issuer.cer")]))

    assert store.anchor("utopia") is not None


def test_an_empty_anchor_list_is_valid(tmp_path: pathlib.Path) -> None:
    """A deployment that trusts nobody yet is a legitimate deployment."""
    assert len(read_trust_anchors(write_anchors(tmp_path, []))) == 0


def test_a_relative_certificate_path_resolves_beside_the_file(tmp_path: pathlib.Path) -> None:
    """So an anchors directory can be moved or mounted as a unit."""
    folder = tmp_path / "anchors"
    folder.mkdir()
    make_certificate(folder)
    store = read_trust_anchors(write_anchors(folder, [entry()]))

    assert store.anchor("utopia") is not None


# The two refusals that matter


def test_algorithms_are_never_inferred(tmp_path: pathlib.Path) -> None:
    """Deriving them would widen trust whenever a key type gained a construction."""
    make_certificate(tmp_path)
    anchors = write_anchors(tmp_path, [entry(permitted_algorithms=None)])

    with pytest.raises(TrustConfigurationError, match="must list permitted_algorithms"):
        read_trust_anchors(anchors)


def test_trust_cannot_be_widened_past_the_certificate(tmp_path: pathlib.Path) -> None:
    """Extending an anchor past its own expiry is overriding the issuer."""
    make_certificate(tmp_path)
    beyond = (NOW + datetime.timedelta(days=900)).isoformat()
    anchors = write_anchors(tmp_path, [entry(not_after=beyond)])

    with pytest.raises(TrustConfigurationError, match="never widened"):
        read_trust_anchors(anchors)


def test_trust_cannot_be_backdated_past_the_certificate(tmp_path: pathlib.Path) -> None:
    """The other end of the same window."""
    make_certificate(tmp_path)
    before = (NOW - datetime.timedelta(days=900)).isoformat()
    anchors = write_anchors(tmp_path, [entry(not_before=before)])

    with pytest.raises(TrustConfigurationError, match="never widened"):
        read_trust_anchors(anchors)


def test_trust_may_be_narrowed(tmp_path: pathlib.Path) -> None:
    """Stopping trust early is an operator's decision to make."""
    make_certificate(tmp_path)
    early = (NOW + datetime.timedelta(days=10)).isoformat()
    store = read_trust_anchors(write_anchors(tmp_path, [entry(not_after=early)]))

    anchor = store.anchor("utopia")

    assert anchor is not None
    assert not anchor.is_valid_at(NOW + datetime.timedelta(days=30))


# Everything else it refuses


def test_an_unknown_algorithm_is_refused_by_name(tmp_path: pathlib.Path) -> None:
    """And the message lists what may be chosen instead."""
    make_certificate(tmp_path)
    anchors = write_anchors(tmp_path, [entry(permitted_algorithms=["RSA_PKCS1V15_SHA1"])])

    with pytest.raises(TrustConfigurationError, match="unknown algorithm"):
        read_trust_anchors(anchors)


def test_an_anchor_without_an_issuer_is_refused(tmp_path: pathlib.Path) -> None:
    """An anchor nobody can name cannot be selected or audited."""
    make_certificate(tmp_path)

    with pytest.raises(TrustConfigurationError, match="must name its issuer"):
        read_trust_anchors(write_anchors(tmp_path, [entry(issuer_id="  ")]))


def test_an_anchor_without_a_certificate_is_refused(tmp_path: pathlib.Path) -> None:
    """There is no key to trust without one."""
    with pytest.raises(TrustConfigurationError, match="must name a certificate"):
        read_trust_anchors(write_anchors(tmp_path, [entry(certificate=None)]))


def test_a_missing_certificate_file_is_refused(tmp_path: pathlib.Path) -> None:
    """Refused rather than skipped: a missing anchor rejects genuine documents."""
    with pytest.raises(TrustConfigurationError, match="cannot read the certificate"):
        read_trust_anchors(write_anchors(tmp_path, [entry()]))


def test_a_file_that_is_not_a_certificate_is_refused(tmp_path: pathlib.Path) -> None:
    """Neither encoding parses, so there is nothing to trust."""
    (tmp_path / "issuer.pem").write_bytes(b"this is not a certificate")

    with pytest.raises(TrustConfigurationError, match=r"not an X\.509 certificate"):
        read_trust_anchors(write_anchors(tmp_path, [entry()]))


def test_two_anchors_cannot_claim_one_issuer(tmp_path: pathlib.Path) -> None:
    """Selection would be arbitrary, and one of them would silently never apply."""
    make_certificate(tmp_path)

    with pytest.raises(TrustConfigurationError, match="not usable"):
        read_trust_anchors(write_anchors(tmp_path, [entry(), entry()]))


def test_a_missing_anchors_file_is_refused(tmp_path: pathlib.Path) -> None:
    """An operator who named a file meant it to exist."""
    with pytest.raises(TrustConfigurationError, match="cannot read the trust anchors"):
        read_trust_anchors(tmp_path / "absent.json")


def test_a_malformed_anchors_file_is_refused(tmp_path: pathlib.Path) -> None:
    """Broken JSON is not an empty trust store."""
    path = tmp_path / "anchors.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(TrustConfigurationError, match="not valid JSON"):
        read_trust_anchors(path)


def test_an_anchors_file_that_is_not_a_list_is_refused(tmp_path: pathlib.Path) -> None:
    """The shape is a list of anchors, and a silent misread is a trust change."""
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps({"issuer_id": "utopia"}), encoding="utf-8")

    with pytest.raises(TrustConfigurationError, match="must be a JSON list"):
        read_trust_anchors(path)


def test_an_entry_that_is_not_an_object_is_refused(tmp_path: pathlib.Path) -> None:
    """Each entry describes one anchor, or the file means something else."""
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps(["utopia"]), encoding="utf-8")

    with pytest.raises(TrustConfigurationError, match="must be an object"):
        read_trust_anchors(path)


def test_an_unreadable_timestamp_is_refused(tmp_path: pathlib.Path) -> None:
    """A date nobody can parse must not silently fall back to the certificate's."""
    make_certificate(tmp_path)
    anchors = write_anchors(tmp_path, [entry(not_after="next Tuesday")])

    with pytest.raises(TrustConfigurationError, match="unreadable not_after"):
        read_trust_anchors(anchors)


def test_a_naive_timestamp_is_refused(tmp_path: pathlib.Path) -> None:
    """An instant without a timezone cannot be compared with the certificate's."""
    make_certificate(tmp_path)
    anchors = write_anchors(tmp_path, [entry(not_after="2026-06-01T00:00:00")])

    with pytest.raises(TrustConfigurationError, match="must carry a timezone"):
        read_trust_anchors(anchors)


def test_a_bom_in_the_anchors_file_is_accepted(tmp_path: pathlib.Path) -> None:
    """PowerShell writes one, and an invisible character must not deny trust."""
    make_certificate(tmp_path)
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps([entry()]), encoding="utf-8-sig")

    assert read_trust_anchors(path).anchor("utopia") is not None


def test_load_certificate_reports_the_path_it_could_not_read(tmp_path: pathlib.Path) -> None:
    """An error at a checkpoint must say which file to look at."""
    with pytest.raises(TrustConfigurationError, match=r"absent\.pem"):
        load_certificate(tmp_path / "absent.pem")
