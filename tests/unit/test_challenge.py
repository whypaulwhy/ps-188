"""The challenge store: what the person is asked, chosen here and answered once.

This store is the whole defence against a recording. If it handed out a
predictable sequence, or accepted one identifier twice, a recording of a single
successful crossing would answer every later one.
"""

from __future__ import annotations

import datetime
import itertools
from typing import Final

from api.challenge import LIFETIME, LIMIT, STEPS, ChallengeStore, sequence
from core.contracts import ChallengeStep

NOW: Final[datetime.datetime] = datetime.datetime(2026, 9, 13, 9, 0, tzinfo=datetime.UTC)
DRAWS: Final[int] = 200
"""Sequences drawn where a property must hold for every one of them."""


# What is asked for


def test_a_challenge_starts_facing_the_camera() -> None:
    """The first photograph is the one compared with the document."""
    assert sequence()[0] is ChallengeStep.CENTRE


def test_a_challenge_asks_for_one_movement_per_photograph() -> None:
    """A sequence longer than the photographs could never be answered."""
    assert len(sequence()) == STEPS


def test_no_movement_is_asked_for_twice_in_a_row() -> None:
    """Twice in a row means two photographs of a head that did not move.

    The liveness check beside this one reads that as a picture held up to the
    camera, so an honest person would be escalated for following instructions.
    """
    for _ in range(DRAWS):
        assert all(before is not after for before, after in itertools.pairwise(sequence()))


def test_the_sequence_is_not_always_the_same() -> None:
    """A predictable sequence is one a recording can be prepared against."""
    assert len({sequence() for _ in range(DRAWS)}) > 1


# Answering one


def test_a_challenge_can_be_answered_once() -> None:
    """The second attempt gets nothing, so a captured identifier is worthless."""
    store = ChallengeStore()
    challenge = store.issue(now=NOW)

    assert store.claim(challenge.challenge_id, now=NOW) == challenge.steps
    assert store.claim(challenge.challenge_id, now=NOW) == ()


def test_an_unknown_identifier_is_not_a_challenge() -> None:
    """Empty means nothing was established, never that something passed."""
    assert ChallengeStore().claim("never-issued", now=NOW) == ()


def test_no_identifier_at_all_is_not_a_challenge() -> None:
    """A device that asks for nothing is a device that was asked nothing."""
    assert ChallengeStore().claim(None, now=NOW) == ()


def test_a_stale_challenge_is_refused() -> None:
    """Otherwise a sequence could be learnt at leisure and answered later."""
    store = ChallengeStore()
    challenge = store.issue(now=NOW)

    assert store.claim(challenge.challenge_id, now=NOW + LIFETIME) == ()


def test_a_challenge_inside_its_lifetime_is_accepted() -> None:
    """The other half, so the test above is not passing on a broken store."""
    store = ChallengeStore()
    challenge = store.issue(now=NOW)
    moments_later = NOW + LIFETIME - datetime.timedelta(seconds=1)

    assert store.claim(challenge.challenge_id, now=moments_later) == challenge.steps


# What the store holds


def test_expired_challenges_are_forgotten_rather_than_kept() -> None:
    """A checkpoint runs for weeks; what nobody answered must not accumulate."""
    store = ChallengeStore()
    store.issue(now=NOW)
    store.issue(now=NOW + LIFETIME * 2)

    assert store.outstanding() == 1


def test_the_store_does_not_grow_without_limit() -> None:
    """Asking for challenges must not be a way to exhaust a checkpoint's memory."""
    store = ChallengeStore()
    for _ in range(LIMIT + 10):
        store.issue(now=NOW)

    assert store.outstanding() == LIMIT
