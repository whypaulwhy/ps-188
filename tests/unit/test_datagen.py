"""Synthetic specimens and the forgeries derived from them.

What matters here is not that the images look right. It is that they are
**reproducible** and that their ground truth is exact, because an evaluation
run scores against that ground truth and a number produced from uncharacterised
data means nothing.
"""

from __future__ import annotations

import pytest

from core.standards.mrz.parse import parse_td3, verify_check_digits
from datagen.forgeries.base import Forgery
from datagen.forgeries.copy_move import CopyMove
from datagen.forgeries.photo_substitution import PhotoSubstitution
from datagen.forgeries.recapture import Recapture
from datagen.forgeries.template_clone import TemplateClone
from datagen.forgeries.text_field_edit import TextFieldEdit
from datagen.synthetic_docs import ISSUING_STATE, WATERMARK, generate_specimen

FORGERIES = [PhotoSubstitution(), TextFieldEdit(), CopyMove(), Recapture(), TemplateClone()]


def test_a_seed_reproduces_a_specimen_byte_for_byte() -> None:
    """An evaluation run has to be replayable, which starts here."""
    assert generate_specimen(seed=7).png == generate_specimen(seed=7).png


def test_different_seeds_give_different_documents() -> None:
    """Otherwise a corpus of a thousand specimens would be one specimen."""
    assert generate_specimen(seed=1).png != generate_specimen(seed=2).png


def test_the_specimen_carries_a_genuine_strip() -> None:
    """Ground truth has to be a real TD3 strip, or nothing downstream means anything."""
    specimen = generate_specimen(seed=1)
    document = parse_td3(list(specimen.mrz))

    assert all(item.matches for item in verify_check_digits(document))
    assert document.surname == "SPECIMEN"


def test_the_issuer_is_fictional() -> None:
    """No synthetic document imitates a real issuing authority. See the module docstring."""
    assert ISSUING_STATE == "UTO"
    assert "NOT A REAL DOCUMENT" in WATERMARK
    assert parse_td3(list(generate_specimen(seed=1).mrz)).issuing_state == "UTO"


@pytest.mark.parametrize("forgery", FORGERIES, ids=lambda f: f.name)
def test_every_forgery_is_reproducible(forgery: Forgery) -> None:
    """The same specimen and seed always produce the same forged document."""
    specimen = generate_specimen(seed=1)

    assert forgery.apply(specimen, seed=5) == forgery.apply(specimen, seed=5)


@pytest.mark.parametrize("forgery", FORGERIES, ids=lambda f: f.name)
def test_every_forgery_actually_changes_the_document(forgery: Forgery) -> None:
    """A forgery that changed nothing would silently inflate a detection rate."""
    specimen = generate_specimen(seed=1)

    assert forgery.apply(specimen, seed=5) != specimen.png


@pytest.mark.parametrize("forgery", FORGERIES, ids=lambda f: f.name)
def test_every_forgery_says_what_it_altered(forgery: Forgery) -> None:
    """An evaluation report carries this, so it cannot be left blank."""
    assert forgery.name.strip()
    assert forgery.alters.strip()
    assert forgery.alters != Forgery.alters


def test_a_cloned_template_stays_internally_consistent() -> None:
    """The hardest case: every field invented, every check digit correct.

    If this document failed arithmetic it would be a poor forgery and would
    flatter the Rung 1 detectors in evaluation.
    """
    forged = TemplateClone().apply(generate_specimen(seed=1), seed=9)
    original = generate_specimen(
        seed=9,
        surname="INVENTED",
        given_names=("OTHER", "PERSON"),
        document_number="Z9999999",
        date_of_birth="850615",
        date_of_expiry="330615",
    )

    assert forged == original.png
    assert all(item.matches for item in verify_check_digits(parse_td3(list(original.mrz))))


def test_the_base_class_refuses_to_be_used_directly() -> None:
    """A forgery with no transformation behind it must not silently produce a clean document."""
    with pytest.raises(NotImplementedError):
        Forgery().apply(generate_specimen(seed=1), seed=1)
