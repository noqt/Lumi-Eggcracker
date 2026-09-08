"""Opt-in real-consumer verification; binaries are test-only and externally pinned."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

from test_monitoring import HEALTHY, ROOT, entrypoint, framed_response

from lumi_eggcracker import monitoring

RULES = ROOT / "integrations/prometheus/eggcracker.rules.yml"
ANNOTATIONS = {
    "EggcrackerExporterDown": "Monitoring exporter unavailable; Eggcracker health is unknown",
    "EggcrackerMetricsMissing": "Expected Eggcracker collection is absent",
    "EggcrackerCollectionStale": "Eggcracker collection has stopped or publication is failing",
    "EggcrackerClockSkew": "Eggcracker collection clock is ahead; freshness is unknown",
    "EggcrackerQueryFailed": "Doctor query is unavailable; reported health is unknown",
    "EggcrackerReportedUnhealthy": "Supervisor reports unready or unhealthy; not a measured containment failure",
}


@unittest.skipUnless(os.environ.get("EGGCRACKER_REAL_CONSUMERS") == "1", "explicit accepted real-consumer CI only")
class PrometheusConsumerTests(unittest.TestCase):
    def test_textfile_scrape_and_actual_alert_rules(self):
        self.assertEqual(os.name, "posix")
        self.assertNotEqual(os.geteuid(), 0)
        exporter = os.environ["EGGCRACKER_NODE_EXPORTER"]
        promtool = os.environ["EGGCRACKER_PROMTOOL"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metrics = root / "health.prom"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            process = subprocess.Popen(
                [exporter, "--web.listen-address=127.0.0.1:" + str(port),
                 "--web.disable-exporter-metrics", "--collector.disable-defaults", "--collector.textfile",
                 "--collector.textfile.directory=" + str(root)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                endpoint = f"http://127.0.0.1:{port}/metrics"
                for _ in range(100):
                    try:
                        with urlopen(endpoint, timeout=1) as response:
                            response.read(262144)
                        break
                    except OSError:
                        if process.poll() is not None:
                            self.fail("loopback exporter failed")
                        time.sleep(0.05)
                else:
                    self.fail("loopback exporter startup timeout")
                for state, valid in ((HEALTHY, True), (None, False), (HEALTHY, True)):
                    payload = json.dumps({"ok": state is not None, "value": state}).encode()
                    with framed_response(root, payload), patch.object(monitoring.time, "time", return_value=60):
                        self.assertEqual(entrypoint(metrics), 0 if valid else 1)
                    with urlopen(endpoint, timeout=3) as response:
                        scrape = response.read(262144).decode()
                    self.assertIn(f"eggcracker_query_valid {int(valid)}\n", scrape)
                    self.assertIn("eggcracker_collection_timestamp_seconds 60\n", scrape)
                    self.assertIn("node_textfile_scrape_error 0\n", scrape)
                    for exposition in (metrics.read_text(), scrape):
                        checked = subprocess.run([promtool, "check", "metrics"], input=exposition, capture_output=True, text=True, timeout=30, check=False)
                        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                    if not valid:
                        self.assertNotIn("eggcracker_reported_ready", scrape)
                        previous = metrics.read_bytes()
                        with urlopen(endpoint, timeout=3) as response:
                            self.assertIn(b"eggcracker_query_valid 0\n", response.read(262144))
                        self.assertEqual(metrics.read_bytes(), previous)
                self._evaluate_rules(promtool, root)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def _evaluate_rules(self, promtool: str, root: Path):
        def series(name, values, instance="one"):
            return {"series": f'{name}{{job="node",instance="{instance}",eggcracker_monitor="true"}}', "values": values}

        def expected(alert, instance="one"):
            return {"exp_labels": {"job": "node", "instance": instance, "eggcracker_monitor": "true", "severity": "warning"}, "exp_annotations": {"summary": ANNOTATIONS[alert]}}

        cases = []
        scenarios = [
            ("healthy", "1+0x8", "0+60x8", "1+0x8", "1+0x8", None, "3m"),
            ("query failure", "1+0x8", "0+60x8", "0+0x8", None, "EggcrackerQueryFailed", "3m"),
            ("stopped", "1+0x8", "0+0x8", "1+0x8", "1+0x8", "EggcrackerCollectionStale", "6m"),
            ("never created", "1+0x8", None, None, None, "EggcrackerMetricsMissing", "3m"),
            ("exporter down", "0+0x8", None, None, None, "EggcrackerExporterDown", "3m"),
            ("future clock", "1+0x8", "600+60x8", "1+0x8", "0+0x8", "EggcrackerClockSkew", "3m"),
            ("unready", "1+0x8", "0+60x8", "1+0x8", "0+0x8", "EggcrackerReportedUnhealthy", "3m"),
            ("discovery_healthy", "1+0x8", "0+60x8", "1+0x8", "0+0x8", "EggcrackerReportedUnhealthy", "3m"),
            ("receipt_storage_healthy", "1+0x8", "0+60x8", "1+0x8", "0+0x8", "EggcrackerReportedUnhealthy", "3m"),
            ("installation_healthy", "1+0x8", "0+60x8", "1+0x8", "0+0x8", "EggcrackerReportedUnhealthy", "3m"),
            ("recovery", "1+0x8", "0+60x8", "0 0 0 1 1 1 1 1 1", "1+0x8", None, "3m"),
        ]
        for name, up, timestamp, valid, ready, alert, moment in scenarios:
            inputs = [series("up", up)]
            health_metric = name if name.endswith("_healthy") else "reported_ready"
            for metric, values in (("collection_timestamp_seconds", timestamp), ("query_valid", valid), (health_metric, ready)):
                if values is not None:
                    inputs.append(series("eggcracker_" + metric, values))
            tests = [{"eval_time": moment, "alertname": candidate, "exp_alerts": [expected(candidate)] if candidate == alert else []} for candidate in ANNOTATIONS]
            if alert:
                before, at = ("5m", "5m30s") if name == "stopped" else ("1m30s", "2m")
                tests.extend([
                    {"eval_time": before, "alertname": alert, "exp_alerts": []},
                    {"eval_time": at, "alertname": alert, "exp_alerts": [expected(alert)]},
                ])
            if name == "recovery":
                tests.append({"eval_time": "2m", "alertname": "EggcrackerQueryFailed", "exp_alerts": [expected("EggcrackerQueryFailed")]})
            cases.append({"name": name, "interval": "1m", "input_series": inputs, "alert_rule_test": tests})
        cases.append({"name": "two targets one missing", "interval": "1m", "input_series": [series("up", "1+0x8"), series("up", "1+0x8", "two"), series("eggcracker_collection_timestamp_seconds", "0+60x8")], "alert_rule_test": [{"eval_time": "3m", "alertname": "EggcrackerMetricsMissing", "exp_alerts": [expected("EggcrackerMetricsMissing", "two")]}]})
        fixture = root / "rule-tests.json"
        fixture.write_text(json.dumps({"rule_files": [str(RULES)], "evaluation_interval": "30s", "tests": cases}), encoding="utf-8")
        for arguments in (["check", "rules", str(RULES)], ["test", "rules", str(fixture)]):
            result = subprocess.run([promtool, *arguments], capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print("MONITORING_REAL_CONSUMER_PASS transitions=healthy,query-loss,stopped,recovery scenarios=12")
