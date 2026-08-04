from __future__ import annotations

import unittest

from lumi_eggcracker.observation import ObservationStore


class ObservationTests(unittest.TestCase):
    def test_observation_expires_and_pid_reuse_identity_is_not_joined(self) -> None:
        store = ObservationStore()
        first = store.observe((42, 100), {"gguf-v3"}, now_ns=1)
        second = store.observe((42, 101), {"llama-elf"}, now_ns=2)
        self.assertEqual(frozenset({"gguf-v3"}), first.evidence)
        self.assertEqual(frozenset({"llama-elf"}), second.evidence)
        store.expire(now_ns=11_000_000_003)
        fresh = store.observe((42, 101), {"llama-elf"}, now_ns=11_000_000_004)
        self.assertEqual(frozenset({"llama-elf"}), fresh.evidence)
