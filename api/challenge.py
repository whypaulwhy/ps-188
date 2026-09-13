"""Challenges: what the person is asked to do, decided after the screening begins.

A liveness check that measures movement can be satisfied by a recording of the
person moving. The defence is to choose the movements at random, here, once the
crossing has started, so that a recording made in advance cannot know them.

**The sequence is chosen by the checkpoint, never by the device.** A page that
chose its own sequence would let anyone holding a recording declare that the
sequence was whatever the recording happens to show.

**Held in memory, single use, short-lived.** A challenge is not an audit record:
what an auditor needs is what the person was *asked*, and that reaches the case
through the evidence. Losing anything outstanding when the process stops is the
safe direction, because an identifier this store does not recognise is refused.
"""

from __future__ import annotations

import dataclasses
import datetime
import secrets
import threading
from typing import Final

from core.contracts import ChallengeStep

STEPS: Final[int] = 4
"""Photographs in one challenge. The first is always centre, for the face comparison."""

LIFETIME: Final[datetime.timedelta] = datetime.timedelta(minutes=3)
"""How long a challenge may be answered. Long enough to photograph a person, no longer."""

LIMIT: Final[int] = 512
"""Most challenges outstanding at once, so a flood of requests cannot grow memory."""

IDENTIFIER_BYTES: Final[int] = 16
"""Random bytes in a challenge identifier. Guessing one must not be worth trying."""


@dataclasses.dataclass(frozen=True)
class Challenge:
    """One sequence of movements, and the instant it was issued."""

    challenge_id: str
    """What the device quotes back when it sends the photographs."""

    steps: tuple[ChallengeStep, ...]
    """The movements asked for, in order. The first photograph is the face-on one."""

    issued_at: datetime.datetime
    """When it was handed out. A challenge answered long afterwards is refused."""

    def expires_at(self) -> datetime.datetime:
        """Return the instant from which this challenge is refused."""
        return self.issued_at + LIFETIME


def sequence() -> tuple[ChallengeStep, ...]:
    """Return a random sequence: centre first, then movements, never twice the same.

    Asking for the same movement twice would mean two photographs of a head in
    the same place, which the liveness check reads as a still picture. So
    consecutive steps always differ, which leaves eight sequences of four.

    Returns:
        The movements, in the order they will be asked for.
    """
    steps = [ChallengeStep.CENTRE]
    for _ in range(STEPS - 1):
        steps.append(secrets.choice([step for step in ChallengeStep if step is not steps[-1]]))
    return tuple(steps)


class ChallengeStore:
    """Hands out challenges and accepts each one exactly once."""

    def __init__(self) -> None:
        """Start with nothing outstanding."""
        self._lock = threading.Lock()
        self._outstanding: dict[str, Challenge] = {}

    def issue(self, *, now: datetime.datetime) -> Challenge:
        """Return a fresh challenge and hold it until it is used or expires.

        Args:
            now: The instant it was asked for.

        Returns:
            The challenge to send to the device.
        """
        challenge = Challenge(
            challenge_id=secrets.token_urlsafe(IDENTIFIER_BYTES),
            steps=sequence(),
            issued_at=now,
        )
        with self._lock:
            self._forget_expired(now)
            while len(self._outstanding) >= LIMIT:
                self._outstanding.pop(next(iter(self._outstanding)))
            self._outstanding[challenge.challenge_id] = challenge
        return challenge

    def claim(
        self, challenge_id: str | None, *, now: datetime.datetime
    ) -> tuple[ChallengeStep, ...]:
        """Return the movements that were asked for, and refuse the identifier after.

        Args:
            challenge_id: What the device says it was asked, or None when it was
                asked nothing.
            now: The instant of the screening.

        Returns:
            The sequence, or empty when the identifier is unknown, already used
            or too old. Empty means nothing was established, which a detector
            reports as a check it could not make and never as one that passed.
        """
        if not challenge_id:
            return ()
        with self._lock:
            self._forget_expired(now)
            challenge = self._outstanding.pop(challenge_id, None)
        return challenge.steps if challenge is not None else ()

    def outstanding(self) -> int:
        """Return how many challenges are waiting to be answered."""
        with self._lock:
            return len(self._outstanding)

    def _forget_expired(self, now: datetime.datetime) -> None:
        """Drop challenges past their lifetime. The caller holds the lock."""
        for identifier, challenge in list(self._outstanding.items()):
            if challenge.expires_at() <= now:
                del self._outstanding[identifier]
