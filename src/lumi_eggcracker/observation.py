"""Short-lived, PID/start-time-bound content observations."""

from __future__ import annotations

import time
from collections.abc import Hashable
from dataclasses import dataclass

MAX_OBSERVATIONS = 4096
MAX_AGE_NS = 10_000_000_000


@dataclass(frozen=True)
class Observation:
    evidence: frozenset[str]
    first_seen_ns: int
    last_seen_ns: int


class ObservationStore:
    def __init__(self) -> None:
        self._values: dict[Hashable, Observation] = {}

    def observe(
        self, identity: Hashable, evidence: set[str], *, now_ns: int | None = None
    ) -> Observation:
        now = time.monotonic_ns() if now_ns is None else now_ns
        self.expire(now_ns=now)
        previous = self._values.get(identity)
        value = Observation(
            frozenset(evidence) | (previous.evidence if previous else frozenset()),
            previous.first_seen_ns if previous else now,
            now,
        )
        self._values[identity] = value
        if len(self._values) > MAX_OBSERVATIONS:
            oldest = min(self._values, key=lambda key: self._values[key].last_seen_ns)
            if oldest != identity:
                self._values.pop(oldest, None)
        return value

    def get(
        self, identity: Hashable, *, now_ns: int | None = None
    ) -> Observation | None:
        self.expire(now_ns=now_ns)
        return self._values.get(identity)

    def identities(self, *, now_ns: int | None = None) -> frozenset[Hashable]:
        self.expire(now_ns=now_ns)
        return frozenset(self._values)

    def expire(self, *, now_ns: int | None = None) -> None:
        now = time.monotonic_ns() if now_ns is None else now_ns
        for key, value in tuple(self._values.items()):
            if now - value.last_seen_ns > MAX_AGE_NS:
                self._values.pop(key, None)
