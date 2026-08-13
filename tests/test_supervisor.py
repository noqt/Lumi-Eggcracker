from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.artifacts import ArtifactEvidence
from lumi_eggcracker.containment import EmptyProof
from lumi_eggcracker.detectors import load_bundled, match
from lumi_eggcracker.discovery import ProcessIdentity, ProcessSnapshot
from lumi_eggcracker.elfmarkers import (
    PYTORCH_ATEN_EVIDENCE_ID,
    PYTORCH_BRIDGE_EVIDENCE_ID,
    RuntimeEvidence,
    with_pytorch_pair,
)
from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.records import RUN_SCHEMA, command_summary, load_run
from lumi_eggcracker.supervisor import Supervisor, _EvidenceCandidate


def record() -> dict[str, object]:
    run_id = "a" * 24
    return {**command_summary(["/bin/true"]), "boot_id": "b" * 36, "cgroup": f"/system.slice/lumi-eggcracker-workload-{run_id}.service", "cgroup_device": 1, "cgroup_inode": 2, "cpu_quota_percent": 400, "created_monotonic_ns": 3, "max_memory_mib": 2048, "max_pids": 8, "name": "demo", "operator_uid": 1001, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": f"lumi-eggcracker-workload-{run_id}.service", "workload_gid": 2001, "workload_uid": 2001}


class SupervisorTests(unittest.TestCase):
    def _instance(self) -> Supervisor:
        value = object.__new__(Supervisor)
        value.policy = {"source_commit": "c" * 40, "workload_uid": 2001}
        value.runs = Path(".")
        value.names = Path(".")
        value.receipts = Path(".")
        value.locks = {}
        value.lock_guard = threading.Lock()
        value.start_lock = threading.Lock()
        value.completed = {}
        value.operations = []
        value.discovery_active = set()
        value.discovery_done = {}
        value.discovery_lock = threading.Lock()
        value.content_scan_tick = 0
        return value

    def test_recently_contained_identity_is_not_reenforced(self) -> None:
        supervisor = self._instance()
        identity = object()
        with supervisor.discovery_lock:
            supervisor.discovery_done[identity] = 1
            self.assertIn(identity, supervisor.discovery_done)

    def test_managed_processes_use_reconciled_in_memory_cgroups(self) -> None:
        supervisor = self._instance()
        cgroup = "/system.slice/lumi-eggcracker-workload-" + "a" * 24 + ".service"
        supervisor.active_cgroups = {cgroup}
        snapshot = ProcessSnapshot(
            ProcessIdentity(10, 100),
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3",),
            ("0::" + cgroup,),
            (),
            (),
        )
        self.assertTrue(supervisor._managed(snapshot))
        self.assertFalse(supervisor._discovery_excluded(snapshot))

    def test_group_refresh_replaces_preexec_gate_snapshot_without_losing_evidence(self) -> None:
        identity = ProcessIdentity(10, 100)
        stale = ProcessSnapshot(
            identity,
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3", "_gate"),
            ("0::/system.slice/lumi-eggcracker-workload-" + "a" * 24 + ".service",),
            (),
            (),
        )
        current = ProcessSnapshot(
            identity,
            2001,
            "/opt/llama-cli",
            "llama-cli",
            ("llama-cli", "-m", "/models/qwen"),
            stale.cgroups,
            (),
            (),
        )
        evidence = ArtifactEvidence("gguf-v3", "GGUF", 1, 2, 4096, "a" * 64)
        candidate = _EvidenceCandidate(stale, (evidence,), (), 123)

        with patch("lumi_eggcracker.supervisor.process_snapshot", return_value=current):
            refreshed = Supervisor._refresh_group((candidate,))

        self.assertEqual(1, len(refreshed))
        self.assertEqual(current, refreshed[0].snapshot)
        self.assertEqual((evidence,), refreshed[0].content)
        with patch("lumi_eggcracker.supervisor.process_snapshot", return_value=None):
            self.assertEqual((), Supervisor._refresh_group((candidate,)))

    def test_selected_match_contains_every_process_in_exact_run_cgroup(self) -> None:
        supervisor = self._instance()
        run_id = "a" * 24
        selected = f"/system.slice/lumi-eggcracker-workload-{run_id}.service"
        evidence_id = ProcessIdentity(10, 100)
        broker_id = ProcessIdentity(11, 101)
        replacement_id = ProcessIdentity(12, 102)
        canary_id = ProcessIdentity(13, 103)
        evidence = ProcessSnapshot(
            evidence_id,
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3",),
            ("0::" + selected,),
            (),
            (),
        )
        broker = ProcessSnapshot(
            broker_id,
            2001,
            "/usr/bin/broker",
            "broker",
            ("broker",),
            ("0::" + selected,),
            (),
            (),
        )
        replacement = ProcessSnapshot(
            replacement_id,
            2001,
            "/usr/bin/replacement",
            "replacement",
            ("replacement",),
            ("0::" + selected,),
            (),
            (),
        )
        canary = ProcessSnapshot(
            canary_id,
            2001,
            "/usr/bin/canary",
            "canary",
            ("canary",),
            ("0::/system.slice/unrelated-canary.service",),
            (),
            (),
        )
        group = (_EvidenceCandidate(evidence, (), (), 1),)

        targets = supervisor._discovery_containment_targets(
            group,
            {
                evidence_id: evidence,
                broker_id: broker,
                replacement_id: replacement,
                canary_id: canary,
            },
        )

        self.assertEqual({evidence_id, broker_id, replacement_id}, targets)

    def test_complete_identity_is_not_suppressed_or_broadened_by_64_partials(self) -> None:
        supervisor = self._instance()
        supervisor.catalogue = load_bundled()
        parent = ProcessIdentity(10, 100)
        parent_snapshot = ProcessSnapshot(
            parent, 2001, "/usr/bin/worker", "worker", ("worker",), (), (), ()
        )
        content = ArtifactEvidence(
            "safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64
        )
        runtime = RuntimeEvidence(
            "pytorch-bridge-aten-pair-pinned-cpu",
            "PyTorch/ATen",
            "BUILD_ID_PAIR",
            (),
        )
        snapshots = {parent: parent_snapshot}
        candidates: list[_EvidenceCandidate] = []
        for offset in range(64):
            identity = ProcessIdentity(100 + offset, 1000 + offset)
            current = ProcessSnapshot(
                identity,
                2001,
                "/usr/bin/python3",
                "python3",
                ("python3",),
                (),
                (),
                (),
                parent=parent,
            )
            snapshots[identity] = current
            candidates.append(_EvidenceCandidate(current, (content,), (), 1))
        complete_identity = ProcessIdentity(999, 1999)
        complete_snapshot = ProcessSnapshot(
            complete_identity,
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3",),
            (),
            (),
            (),
            parent=parent,
        )
        snapshots[complete_identity] = complete_snapshot
        candidates.append(
            _EvidenceCandidate(complete_snapshot, (content,), (runtime,), 2)
        )

        correlated = supervisor._correlate(candidates, snapshots)
        self.assertEqual(1, len(correlated))
        self.assertEqual(65, len(correlated[0][0]))

        groups = supervisor._content_groups(candidates, snapshots)
        self.assertEqual(1, len(groups))
        self.assertEqual(
            (complete_identity,),
            tuple(item.snapshot.identity for item in groups[0].witness),
        )
        self.assertEqual(65, len(groups[0].scope))

    def test_complete_sibling_storm_is_one_full_component_enforcement_scope(self) -> None:
        supervisor = self._instance()
        supervisor.catalogue = load_bundled()
        parent = ProcessIdentity(20, 200)
        snapshots = {
            parent: ProcessSnapshot(
                parent, 2001, "/usr/bin/worker", "worker", ("worker",), (), (), ()
            )
        }
        content = ArtifactEvidence(
            "safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64
        )
        runtime = RuntimeEvidence(
            "pytorch-bridge-aten-pair-pinned-cpu",
            "PyTorch/ATen",
            "BUILD_ID_PAIR",
            (),
        )
        candidates: list[_EvidenceCandidate] = []
        for offset in range(18):
            current_identity = ProcessIdentity(21 + offset, 201 + offset)
            current = ProcessSnapshot(
                current_identity,
                2001,
                "/usr/bin/python3",
                "python3",
                ("python3",),
                (),
                (),
                (),
                parent=parent,
            )
            snapshots[current_identity] = current
            candidates.append(
                _EvidenceCandidate(current, (content,), (runtime,), 1)
            )

        groups = supervisor._content_groups(candidates, snapshots)

        self.assertEqual(1, len(groups))
        self.assertEqual(18, len(groups[0].witness))
        self.assertEqual(18, len(groups[0].scope))
        self.assertEqual(
            {parent, *(candidate.snapshot.identity for candidate in candidates)},
            supervisor._discovery_containment_targets(groups[0].scope, snapshots),
        )

    def test_partial_peer_is_scope_but_not_witness_for_complete_identity(self) -> None:
        supervisor = self._instance()
        supervisor.catalogue = load_bundled()
        parent = ProcessIdentity(40, 400)
        snapshots = {
            parent: ProcessSnapshot(
                parent, 2001, "/usr/bin/worker", "worker", ("worker",), (), (), ()
            )
        }
        content = ArtifactEvidence(
            "safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64
        )
        runtime = RuntimeEvidence(
            "pytorch-bridge-aten-pair-pinned-cpu",
            "PyTorch/ATen",
            "BUILD_ID_PAIR",
            (),
        )
        complete_identity = ProcessIdentity(41, 401)
        partial_identity = ProcessIdentity(42, 402)
        complete = ProcessSnapshot(
            complete_identity,
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3",),
            (),
            (),
            (),
            parent=parent,
        )
        partial = ProcessSnapshot(
            partial_identity,
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3",),
            (),
            (),
            (),
            parent=parent,
        )
        snapshots.update({complete_identity: complete, partial_identity: partial})

        groups = supervisor._content_groups(
            [
                _EvidenceCandidate(complete, (content,), (runtime,), 1),
                _EvidenceCandidate(partial, (content,), (), 1),
            ],
            snapshots,
        )

        self.assertEqual(1, len(groups))
        self.assertEqual((complete_identity,), tuple(item.snapshot.identity for item in groups[0].witness))
        self.assertEqual(
            {complete_identity, partial_identity},
            {item.snapshot.identity for item in groups[0].scope},
        )

    def test_redundant_complete_sibling_pairs_expand_enforcement_scope(self) -> None:
        supervisor = self._instance()
        supervisor.catalogue = load_bundled()
        parent = ProcessIdentity(20, 200)
        snapshots = {
            parent: ProcessSnapshot(
                parent,
                2001,
                "/usr/bin/worker",
                "worker",
                ("worker",),
                (),
                (),
                (),
            )
        }
        content = ArtifactEvidence(
            "safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64
        )
        runtime = RuntimeEvidence(
            "pytorch-bridge-aten-pair-pinned-cpu",
            "PyTorch/ATen",
            "BUILD_ID_PAIR",
            (),
        )
        candidates: list[_EvidenceCandidate] = []
        for offset, evidence in enumerate(
            ((content, None), (content, None), (None, runtime), (None, runtime))
        ):
            identity = ProcessIdentity(21 + offset, 201 + offset)
            current = ProcessSnapshot(
                identity,
                2001,
                "/usr/bin/python3",
                "python3",
                ("python3",),
                (),
                (),
                (),
                parent=parent,
            )
            snapshots[identity] = current
            candidates.append(
                _EvidenceCandidate(
                    current,
                    (evidence[0],) if evidence[0] is not None else (),
                    (evidence[1],) if evidence[1] is not None else (),
                    1,
                )
            )

        groups = supervisor._content_groups(candidates, snapshots)
        self.assertGreaterEqual(len(groups), 1)
        for group in groups:
            self.assertLessEqual(len(group.witness), 3)
            self.assertEqual(4, len(group.scope))
            self.assertEqual(
                {parent, *(candidate.snapshot.identity for candidate in candidates)},
                supervisor._discovery_containment_targets(group.scope, snapshots),
            )

    def test_heartbeat_stops_when_no_scan_completed_within_health_bound(self) -> None:
        supervisor = self._instance()
        supervisor.discovery_thread = type(
            "LiveThread", (), {"is_alive": lambda _self: True}
        )()
        supervisor.last_heartbeat_sent = 0.0
        supervisor.last_scan_completed_ns = time.monotonic_ns() - 2_000_000_000
        supervisor.discovery_failures = 0
        with patch("lumi_eggcracker.supervisor.socket.socket") as socket_factory:
            supervisor._heartbeat()
        socket_factory.assert_not_called()

    def test_discovery_window_generation_survives_supervisor_restart(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "discovery-progress.json"
            first = self._instance()
            first.discovery_progress_path = path
            first._reserve_discovery_window()
            second = self._instance()
            second.discovery_progress_path = path
            second._reserve_discovery_window()

            self.assertEqual(0, first.discovery_window_generation)
            self.assertEqual(1, second.discovery_window_generation)
            self.assertEqual(64, second._window_start(64))
            second.content_scan_tick = 2
            self.assertEqual(128, second._window_start(64))
            self.assertEqual(
                2, json.loads(path.read_text(encoding="utf-8"))["generation"]
            )

    def test_invalid_discovery_progress_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "discovery-progress.json"
            path.write_text('{"generation": true}', encoding="utf-8")
            supervisor = self._instance()
            supervisor.discovery_progress_path = path

            with self.assertRaises(JsonInputError):
                supervisor._reserve_discovery_window()

    def test_containment_orders_direct_kill_before_receipt_state_and_cleanup(self) -> None:
        supervisor = self._instance()
        response = {"result": "TERMINATED", "cleanup": {"attempted": False}}
        with patch("lumi_eggcracker.supervisor.validate_identity", return_value=Path("/owned")), patch("lumi_eggcracker.supervisor.kill_path", return_value=(11, 12)), patch("lumi_eggcracker.supervisor.verify_empty", return_value=(13, EmptyProof(True, 1, 0, []))), patch.object(supervisor, "_cleanup", side_effect=lambda _: supervisor.operations.append("cleanup") or {}), patch("lumi_eggcracker.supervisor.make_receipt", return_value=response), patch("lumi_eggcracker.supervisor.write_atomic"), patch.object(supervisor, "_store", side_effect=lambda *_: supervisor.operations.append("durable-state")):
            result = supervisor._contain(record(), "OPERATOR", 10)
        self.assertEqual("TERMINATED", result["result"])
        self.assertEqual("cgroup.kill", supervisor.operations[0])
        self.assertLess(supervisor.operations.index("cgroup.kill"), supervisor.operations.index("durable-receipt"))
        self.assertLess(supervisor.operations.index("durable-receipt"), supervisor.operations.index("cleanup"))

    def test_exact_empty_cgroup_allows_normal_completion_without_systemctl(self) -> None:
        supervisor = self._instance()
        saved: list[dict[str, object]] = []
        with patch("lumi_eggcracker.supervisor.events_from_fd", return_value={"populated": 0}), patch.object(supervisor, "_store", side_effect=lambda value: saved.append(value.copy())):
            self.assertTrue(supervisor._complete_allowed(record(), 42))
        self.assertEqual("COMPLETED_ALLOWED", saved[0]["state"])

    def test_collected_empty_cgroup_allows_normal_completion_with_exact_proof(self) -> None:
        supervisor = self._instance()
        item = record()
        with patch.object(supervisor, "_watch_once", side_effect=JsonInputError("owned cgroup is unavailable")), patch("lumi_eggcracker.supervisor.verify_empty", return_value=(1, EmptyProof(True, 0, 0, []))), patch.object(supervisor, "_store") as stored:
            supervisor._watch(item)
        stored.assert_called_once()
        self.assertEqual("COMPLETED_ALLOWED", item["state"])

    def test_recovery_accepts_only_an_exact_empty_collected_cgroup(self) -> None:
        supervisor = self._instance()
        item = record()
        with tempfile.TemporaryDirectory() as raw:
            supervisor.runs = Path(raw)
            (supervisor.runs / ("a" * 24 + ".json")).write_text(__import__("json").dumps(item), encoding="utf-8")
            with patch.object(supervisor, "_contain", side_effect=JsonInputError("containment failed: owned cgroup is unavailable")), patch("lumi_eggcracker.supervisor.verify_empty", return_value=(1, EmptyProof(True, 0, 0, []))), patch.object(supervisor, "_mark_completed") as completed:
                supervisor._recover()
        completed.assert_called_once_with(item)

    def test_recovery_promotes_collected_failure_after_exact_empty_proof(self) -> None:
        supervisor = self._instance()
        item = record()

        def fail_containment(value: dict[str, object], _trigger: str) -> None:
            value["state"] = "CONTAINMENT_FAILED"
            raise JsonInputError("containment failed: owned cgroup is unavailable")

        with tempfile.TemporaryDirectory() as raw:
            supervisor.runs = Path(raw)
            (supervisor.runs / ("a" * 24 + ".json")).write_text(
                __import__("json").dumps(item), encoding="utf-8"
            )
            with patch.object(supervisor, "_contain", side_effect=fail_containment), patch(
                "lumi_eggcracker.supervisor.verify_empty",
                return_value=(1, EmptyProof(True, 0, 0, [])),
            ), patch.object(supervisor, "_mark_completed") as completed:
                supervisor._recover()
        self.assertEqual("RUNNING", item["state"])
        completed.assert_called_once_with(item)

    def test_status_is_read_only(self) -> None:
        supervisor = self._instance()
        item = record()
        with patch.object(supervisor, "_load", return_value=item), patch.object(supervisor, "_store") as stored:
            value = supervisor.handle({"action": "status", "args": {"name": "demo"}})
        self.assertEqual("RUNNING", value["state"])
        stored.assert_not_called()

    def test_status_resolves_the_latest_terminal_run_after_name_reuse_is_enabled(self) -> None:
        supervisor = self._instance()
        item = record(); item["state"] = "COMPLETED_ALLOWED"
        with patch.object(supervisor, "_load", side_effect=JsonInputError("gone")), patch.object(supervisor, "_latest_by_name", return_value=item), patch.object(supervisor, "_store") as stored:
            value = supervisor.handle({"action": "status", "args": {"name": "demo"}})
        self.assertEqual("COMPLETED_ALLOWED", value["state"])
        stored.assert_not_called()

    def test_run_records_are_keyed_by_run_id_and_name_pointer_is_removed_when_terminal(self) -> None:
        supervisor = self._instance()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            supervisor.runs = root / "runs"; supervisor.names = root / "names"
            item = record()
            supervisor._store(item)
            self.assertTrue((supervisor.runs / ("a" * 24 + ".json")).is_file())
            self.assertTrue((supervisor.names / "demo.json").is_file())
            item["state"] = "TERMINATED"
            supervisor._store(item)
            self.assertFalse((supervisor.names / "demo.json").exists())

    def test_autonomous_kill_terminal_state_wins_completion_race(self) -> None:
        supervisor = self._instance()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            supervisor.runs = root / "runs"
            supervisor.names = root / "names"
            item = record()
            supervisor._store(item)
            stale_watcher_record = item.copy()
            supervisor._mark_discovered_runs_terminated({str(item["cgroup"])})
            self.assertEqual(
                "TERMINATED", load_run(supervisor.runs, str(item["run_id"]))["state"]
            )
            self.assertFalse(supervisor._mark_completed(stale_watcher_record))
            self.assertEqual(
                "TERMINATED", load_run(supervisor.runs, str(item["run_id"]))["state"]
            )

    def test_correlation_requires_live_same_uid_parent_or_sibling_relation(self) -> None:
        supervisor = self._instance()
        root = ProcessIdentity(10, 100)
        left_identity = ProcessIdentity(11, 101)
        right_identity = ProcessIdentity(12, 102)
        left = ProcessSnapshot(left_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=root)
        right = ProcessSnapshot(right_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=root)
        root_snapshot = ProcessSnapshot(root, 2001, "/usr/bin/worker", "worker", ("worker",), (), (), ())
        content = ArtifactEvidence("safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64)
        runtime = RuntimeEvidence("pytorch-bridge-aten-pair-pinned-cpu", "PyTorch/ATen", "BUILD_ID_PAIR", ())
        left_candidate = _EvidenceCandidate(left, (content,), (), 1)
        right_candidate = _EvidenceCandidate(right, (), (runtime,), 2)
        related, boundary = supervisor._related(left_candidate, right_candidate, {root: root_snapshot, left_identity: left, right_identity: right})
        self.assertTrue(related)
        self.assertEqual("sibling", boundary)
        unrelated_root = ProcessIdentity(1, 1)
        right_unrelated = ProcessSnapshot(right_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=unrelated_root)
        root_snapshot = ProcessSnapshot(unrelated_root, 0, "/sbin/init", "init", ("init",), (), (), ())
        related, _boundary = supervisor._related(left_candidate, _EvidenceCandidate(right_unrelated, (), (runtime,), 2), {unrelated_root: root_snapshot, left_identity: left, right_identity: right_unrelated})
        self.assertFalse(related)

    def test_related_pair_is_synthesized_but_unrelated_pair_is_not(self) -> None:
        supervisor = self._instance()
        common = ProcessIdentity(30, 300)
        left_identity = ProcessIdentity(31, 301)
        right_identity = ProcessIdentity(32, 302)
        left = ProcessSnapshot(left_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=common)
        right = ProcessSnapshot(right_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=common)
        root = ProcessSnapshot(common, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), ())
        content = ArtifactEvidence("safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64)
        bridge = RuntimeEvidence(PYTORCH_BRIDGE_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID", ())
        aten = RuntimeEvidence(PYTORCH_ATEN_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID", ())
        related_groups = supervisor._correlate(
            [_EvidenceCandidate(left, (content,), (bridge,), 1), _EvidenceCandidate(right, (), (aten,), 2)],
            {common: root, left_identity: left, right_identity: right},
        )
        self.assertEqual(1, len(related_groups))
        group = related_groups[0][0]
        runtimes = with_pytorch_pair(item for candidate in group for item in candidate.runtimes)
        self.assertIsNotNone(
            match(
                load_bundled(),
                left,
                evidence={
                    "MODEL_CONTENT": {content.evidence_id},
                    "MODEL_RUNTIME": {item.evidence_id for item in runtimes},
                },
            )
        )
        unrelated_root = ProcessIdentity(40, 400)
        unrelated = ProcessSnapshot(right_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=unrelated_root)
        unrelated_groups = supervisor._correlate(
            [_EvidenceCandidate(left, (content,), (bridge,), 1), _EvidenceCandidate(unrelated, (), (aten,), 2)],
            {common: root, left_identity: left, unrelated_root: ProcessSnapshot(unrelated_root, 0, "/sbin/init", "init", ("init",), (), (), ()), right_identity: unrelated},
        )
        self.assertEqual(2, len(unrelated_groups))
        self.assertTrue(
            all(
                match(
                    load_bundled(),
                    group[0].snapshot,
                    evidence={
                        "MODEL_CONTENT": {item.evidence_id for item in group[0].content},
                        "MODEL_RUNTIME": {item.evidence_id for item in with_pytorch_pair(group[0].runtimes)},
                    },
                )
                is None
                for group, _boundary in unrelated_groups
            )
        )

    def test_unrelated_same_uid_partial_candidates_do_not_join_by_common_root(self) -> None:
        supervisor = self._instance()
        common = ProcessIdentity(1, 1)
        left_id = ProcessIdentity(21, 201)
        right_id = ProcessIdentity(22, 202)
        left = ProcessSnapshot(left_id, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=common)
        right = ProcessSnapshot(right_id, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=common)
        root = ProcessSnapshot(common, 0, "/sbin/init", "init", ("init",), (), (), ())
        content = ArtifactEvidence("safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64)
        runtime = RuntimeEvidence("pytorch-bridge-aten-pair-pinned-cpu", "PyTorch/ATen", "BUILD_ID_PAIR", ())
        with patch.object(supervisor, "_owned_cgroup", return_value=None):
            groups = supervisor._correlate(
                [_EvidenceCandidate(left, (content,), (), 1), _EvidenceCandidate(right, (), (runtime,), 2)],
                {common: root, left_id: left, right_id: right},
            )
        self.assertEqual(2, len(groups))
        self.assertTrue(all(len(value[0]) == 1 for value in groups))
