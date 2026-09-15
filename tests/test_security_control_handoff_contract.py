"""Inert contract model only: no Eggcracker imports or real control operations."""

import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from threading import Barrier, Lock


@dataclass(frozen=True)
class Request:
    request_id: str
    handle: str
    issued: int
    expires: int


@dataclass(frozen=True)
class Fixture:
    owner: str
    generation: str
    expires: int


@dataclass(frozen=True)
class Outcome:
    code: str
    accepted: bool = False
    dispatched: bool = False
    observation: str = "NONE"
    verified_stop: bool = False
    scope: str = "FABRICATED_OWNED_FIXTURE_ONLY"

    def views(self):
        # Both presentations contain precisely the same bounded facts.
        facts = asdict(self)
        return {
            "developer": facts,
            "stakeholder": dict(facts),
        }


class FakeReceiver:
    def __init__(self, observation="SIMULATED_COMPLETE"):
        self.observation = observation
        self.calls = []

    def receive(self, fixture):
        self.calls.append(fixture)
        return self.observation


class ContractExample:
    """Synchronous test harness, not an authentication or production interface.

    The test supervisor supplies caller identity, grants, clock and registry.
    The request cannot supply them. One lock covers revalidation and fake call.
    All state is in memory; restarting loses it and is NOT safe replay recovery.
    """

    def __init__(self, receiver=None):
        self.receiver = receiver if receiver is not None else FakeReceiver()
        self.lock = Lock()
        self.registry = {"fixture-handle-a": Fixture("owner-a", "generation-a", 120)}
        self.current = {"owner-a": "generation-a"}
        self.grants = {("caller-a", "owner-a", "generation-a")}
        self.seen = {}
        self.dispatched_instances = set()
        self.supported = True

    def replace_fixture(self):
        with self.lock:
            # Old token stays bound to old generation: no token reuse/transfer.
            self.current["owner-a"] = "generation-b"
            self.registry["fixture-handle-b"] = Fixture("owner-a", "generation-b", 120)

    def submit(self, raw, *, trusted_caller="caller-a", now=100):
        with self.lock:
            if type(raw) is not dict or set(raw) != {"request_id", "handle", "issued", "expires"}:
                return Outcome("MALFORMED")
            if any(
                type(raw[k]) is not str
                or not 1 <= len(raw[k]) <= 64
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in raw[k])
                for k in ("request_id", "handle")
            ):
                return Outcome("MALFORMED")
            if any(type(raw[k]) is not int for k in ("issued", "expires")):
                return Outcome("MALFORMED")
            request = Request(**raw)
            if not 0 <= request.issued <= now < request.expires <= request.issued + 30:
                return Outcome("NOT_FRESH")
            fixture = self.registry.get(request.handle)
            if fixture is None:
                return Outcome("UNKNOWN_HANDLE")
            if now >= fixture.expires:
                return Outcome("HANDLE_EXPIRED")
            if self.current.get(fixture.owner) != fixture.generation:
                return Outcome("STALE_HANDLE")
            if (trusted_caller, fixture.owner, fixture.generation) not in self.grants:
                return Outcome("NOT_AUTHORIZED")
            if not self.supported:
                return Outcome("UNSUPPORTED")
            key = (trusted_caller, request.request_id)
            if key in self.seen:
                return Outcome("DUPLICATE" if self.seen[key] == request else "REPLAY_CONFLICT")
            instance = (fixture.owner, fixture.generation)
            if instance in self.dispatched_instances:
                return Outcome("ALREADY_DISPATCHED")
            self.seen[key] = request
            self.dispatched_instances.add(instance)
            # Accepted does not imply dispatched or observed. No receiver => no call.
            if self.receiver is None:
                return Outcome("NO_RECEIVER", accepted=True)
            try:
                observed = self.receiver.receive(fixture)
            except Exception:  # noqa: BLE001 - never expose raw fake-receiver failure data.
                return Outcome(
                    "FAKE_RECEIVER_FAILED", accepted=True, dispatched=True, observation="FAILED"
                )
            allowed = {"SIMULATED_COMPLETE", "PARTIAL", "UNKNOWN", "FAILED"}
            if type(observed) is not str or observed not in allowed:
                observed = "UNKNOWN"
            return Outcome("FAKE_DISPATCHED", accepted=True, dispatched=True, observation=observed)


def request(**changes):
    value = {"request_id": "request-a", "handle": "fixture-handle-a", "issued": 95, "expires": 110}
    value.update(changes)
    return value


class SecurityControlHandoffContractTests(unittest.TestCase):
    def assert_refused(self, model, raw, code, **context):
        before = len(model.receiver.calls)
        outcome = model.submit(raw, **context)
        self.assertEqual(outcome, Outcome(code))
        self.assertEqual(len(model.receiver.calls), before)
        return outcome

    def test_valid_one_owned_fixture_and_two_identical_views(self):
        model = ContractExample()
        result = model.submit(request())
        self.assertEqual(model.receiver.calls, [Fixture("owner-a", "generation-a", 120)])
        self.assertEqual(result, Outcome("FAKE_DISPATCHED", True, True, "SIMULATED_COMPLETE"))
        self.assertEqual(result.views()["developer"], result.views()["stakeholder"])
        self.assertFalse(result.verified_stop)

    def test_malformed_never_echoes_raw_input(self):
        for raw in (
            None,
            [],
            {},
            request(pid=999),
            request(caller="caller-a"),
            request(handle="/private/raw"),
            request(request_id="x" * 65),
            request(issued=True),
            request(expires="110"),
            request(handle=[]),
        ):
            with self.subTest(raw_type=type(raw).__name__):
                result = self.assert_refused(ContractExample(), raw, "MALFORMED")
                self.assertNotIn("private", str(result.views()))
                self.assertEqual(result.views()["developer"], result.views()["stakeholder"])

    def test_expired_future_and_excessive_lifetime(self):
        for raw in (
            request(expires=100),
            request(issued=101),
            request(issued=-1),
            request(expires=200),
            request(issued=110, expires=100),
        ):
            self.assert_refused(ContractExample(), raw, "NOT_FRESH")

    def test_unknown_out_of_scope_and_unauthorized(self):
        self.assert_refused(ContractExample(), request(handle="unknown"), "UNKNOWN_HANDLE")
        self.assert_refused(
            ContractExample(), request(), "NOT_AUTHORIZED", trusted_caller="caller-other"
        )
        model = ContractExample()
        model.registry["fixture-other"] = Fixture("owner-other", "generation-other", 120)
        model.current["owner-other"] = "generation-other"
        self.assert_refused(model, request(handle="fixture-other"), "NOT_AUTHORIZED")

    def test_handle_expired_and_unsupported(self):
        model = ContractExample()
        model.registry["fixture-handle-a"] = Fixture("owner-a", "generation-a", 100)
        self.assert_refused(model, request(), "HANDLE_EXPIRED")
        model = ContractExample()
        model.supported = False
        self.assert_refused(model, request(), "UNSUPPORTED")

    def test_replace_between_request_creation_and_dispatch(self):
        model = ContractExample()
        raw = request()
        model.replace_fixture()
        self.assert_refused(model, raw, "STALE_HANDLE")
        self.assert_refused(model, request(handle="fixture-handle-b"), "NOT_AUTHORIZED")

    def test_duplicate_and_conflicting_replay_do_not_redispatch(self):
        model = ContractExample()
        model.submit(request())
        self.assert_refused(model, request(), "DUPLICATE")
        self.assert_refused(model, request(expires=109), "REPLAY_CONFLICT")
        self.assert_refused(model, request(request_id="request-b"), "ALREADY_DISPATCHED")

    def test_duplicate_revalidates_authority_freshness_and_binding(self):
        for mutation, code in (
            (lambda m: m.grants.clear(), "NOT_AUTHORIZED"),
            (lambda m: m.replace_fixture(), "STALE_HANDLE"),
        ):
            model = ContractExample()
            model.submit(request())
            mutation(model)
            self.assert_refused(model, request(), code)
        model = ContractExample()
        model.submit(request())
        self.assert_refused(model, request(), "NOT_FRESH", now=110)

    def test_same_id_cannot_substitute_an_authorized_replacement(self):
        model = ContractExample()
        model.submit(request())
        model.replace_fixture()
        model.grants.add(("caller-a", "owner-a", "generation-b"))
        self.assert_refused(model, request(handle="fixture-handle-b"), "REPLAY_CONFLICT")
        result = model.submit(request(request_id="request-b", handle="fixture-handle-b"))
        self.assertTrue(result.dispatched)
        self.assertEqual(
            [f.generation for f in model.receiver.calls], ["generation-a", "generation-b"]
        )

    def test_fake_partial_unknown_failed_and_unexpected_never_stop(self):
        for observation in (
            "SIMULATED_COMPLETE",
            "PARTIAL",
            "UNKNOWN",
            "FAILED",
            "private-raw-response",
            None,
            {"private": "raw"},
        ):
            model = ContractExample(FakeReceiver(observation))
            result = model.submit(request())
            self.assertTrue(result.accepted)
            self.assertTrue(result.dispatched)
            self.assertFalse(result.verified_stop)
            self.assertNotIn("private", str(result.views()))
            self.assertEqual(result.views()["developer"], result.views()["stakeholder"])
            self.assert_refused(model, request(), "DUPLICATE")

    def test_receiver_failure_is_unconfirmed_and_not_retried(self):
        class FailingReceiver(FakeReceiver):
            def receive(self, fixture):
                self.calls.append(fixture)
                raise ValueError("private raw failure")

        model = ContractExample(FailingReceiver())
        result = model.submit(request())
        self.assertEqual(result, Outcome("FAKE_RECEIVER_FAILED", True, True, "FAILED"))
        self.assertNotIn("private", str(result.views()))
        self.assert_refused(model, request(), "DUPLICATE")

    def test_accepted_without_dispatch_is_not_observed(self):
        model = ContractExample()
        model.receiver = None
        self.assertEqual(model.submit(request()), Outcome("NO_RECEIVER", accepted=True))

    def test_concurrent_duplicate_and_distinct_ids_dispatch_only_once(self):
        for ids, refusal in (
            (["request-a"] * 4, "DUPLICATE"),
            (["request-a", "request-b", "request-c", "request-d"], "ALREADY_DISPATCHED"),
        ):
            model = ContractExample()
            barrier = Barrier(4)

            def submit(request_id, barrier=barrier, model=model):
                barrier.wait(timeout=5)
                return model.submit(request(request_id=request_id))

            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(submit, ids))
            self.assertEqual(len(model.receiver.calls), 1)
            self.assertEqual(
                sorted(r.code for r in results), sorted(["FAKE_DISPATCHED"] + [refusal] * 3)
            )
            self.assertTrue(all(not r.verified_stop for r in results))


if __name__ == "__main__":
    unittest.main()
