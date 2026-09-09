"""Predeclared toy detectors using only defender-visible synthetic telemetry."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

ARMS = (
    "positive-control", "conventional-prevention", "rate", "conventional-rules",
    "correlation", "alert-only", "remove-timing", "remove-sequence", "remove-identity",
)


@dataclass(frozen=True)
class Event:
    run_id: str
    allocation: str
    generation: int
    event_id: int
    sensor: str
    event_tick: int
    available_tick: int
    action: str
    resource: str
    identity: str


class Detector:
    """Bounded per-run detector; no scenario label or protected-effect oracle input."""

    def __init__(self, arm):
        if arm not in ARMS:
            raise ValueError("unknown arm")
        self.arm = arm
        self.seen = set()
        self.recent = deque(maxlen=256)
        self.denial = None
        self.last_available = 0
        self.detected = None
        self.run_id = None

    def accept(self, event: Event, now: int):
        if not isinstance(event, Event) or event.allocation != "A" or event.generation != 1:
            raise ValueError("unexpected event scope")
        if (type(event.run_id) is not str or not 0 < len(event.run_id) <= 64
                or self.run_id is not None and event.run_id != self.run_id):
            raise ValueError("unexpected run identity")
        if not 0 <= event.event_tick <= event.available_tick <= now:
            raise ValueError("event unavailable or inconsistent")
        if event.available_tick < self.last_available:
            raise ValueError("out-of-order delivery")
        self.run_id = event.run_id
        self.last_available = event.available_tick
        if self.detected is not None or event.event_id in self.seen:
            return self.detected
        if len(self.seen) >= 256:
            raise ValueError("run event budget exceeded")
        self.seen.add(event.event_id)
        if event.action == "gap":
            self.denial = None
            self.recent.clear()
            return self.detected
        self.recent.append(event.available_tick)
        while self.recent and event.available_tick - self.recent[0] > 10:
            self.recent.popleft()
        conventional = event.action == "tamper" or (
            event.action == "deny" and event.resource == "protected")
        sequence_signal = False
        if self.denial is not None:
            tick, identity, resource = self.denial
            time_match = self.arm == "remove-timing" or event.available_tick - tick <= 50
            identity_match = self.arm != "remove-identity" and (
                event.identity != identity or event.resource != resource)
            sequence_signal = time_match and identity_match and self.arm != "remove-sequence"
        if event.action == "deny":
            self.denial = (event.available_tick, event.identity, event.resource)
        if self.arm in {"positive-control", "conventional-prevention"}:
            triggered = False
        elif self.arm == "rate":
            triggered = len(self.recent) >= 8
        elif self.arm == "conventional-rules":
            triggered = conventional
        else:
            triggered = conventional or sequence_signal
        if triggered:
            self.detected = now
        return self.detected
