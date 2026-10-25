from __future__ import annotations

import contextlib
import io
import json
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lumi_eggcracker import gguf_file_observe as observer
from lumi_eggcracker.jsonio import JsonInputError, canonical_bytes


def gguf(*, version: int = 3, tensors: int = 1, metadata: int = 0, padding: int = 64) -> bytes:
    return b"GGUF" + struct.pack("<IQQ", version, tensors, metadata) + b"\0" * padding


class GgufFileObserveTests(unittest.TestCase):
    def _observe(self, path: Path) -> dict[str, object]:
        return observer.observe_file(path)

    def test_valid_v2_and_v3_are_content_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for version in (2, 3):
                path = root / f"opaque-{version}"
                body = gguf(version=version)
                path.write_bytes(body)
                report = self._observe(path)
                self.assertEqual("FILE_EVIDENCE_ONLY", report["result"])
                self.assertEqual(
                    {
                        "MODEL_CONTENT": [f"gguf-v{version}"],
                        "MODEL_RUNTIME": [],
                        "MODEL_TOPOLOGY": [],
                    },
                    report["content_evidence"],
                )
                evidence = report["evidence"]
                self.assertIsInstance(evidence, dict)
                assert isinstance(evidence, dict)
                self.assertEqual(version, evidence["gguf_version"])
                self.assertEqual(len(body), evidence["inspected_prefix_bytes"])
                self.assertEqual("first_prefix_only", evidence["hash_scope"])

    def test_schema_and_output_are_exactly_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "public-format"
            path.write_bytes(gguf(version=3))
            first = self._observe(path)
            second = self._observe(path)
            self.assertEqual(first, second)
            encoded = canonical_bytes(first)
            self.assertEqual(encoded, canonical_bytes(second))
            self.assertLessEqual(len(encoded), observer.MAX_OUTPUT_BYTES)
            self.assertEqual(observer.SCHEMA, first["schema_version"])
            self.assertTrue(encoded.endswith(b"\n"))

    def test_every_content_profile_is_explained_and_none_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "model"
            path.write_bytes(gguf())
            report = self._observe(path)
            catalogue = report["catalogue"]
            self.assertIsInstance(catalogue, dict)
            assert isinstance(catalogue, dict)
            profiles = catalogue["content_profiles"]
            self.assertEqual(4, len(profiles))
            self.assertEqual([], catalogue["complete_profiles"])
            for profile in profiles:
                self.assertFalse(profile["complete"])
                for group in profile["groups"]:
                    self.assertEqual(
                        {"group", "required_any", "supplied", "missing", "satisfied"},
                        set(group),
                    )
                    self.assertIsInstance(group["satisfied"], bool)

    def test_rejects_malformed_truncated_bad_version_count_and_declared_bounds(self) -> None:
        invalid = (
            b"GGUF",
            b"GGUF" + struct.pack("<IQQ", 1, 1, 0) + b"\0" * 64,
            gguf(tensors=0),
            gguf(tensors=10_000_001),
            gguf(metadata=10_000_001),
            gguf(tensors=1, metadata=1, padding=0),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index, body in enumerate(invalid):
                path = root / str(index)
                path.write_bytes(body)
                with self.subTest(index=index), self.assertRaises(JsonInputError):
                    self._observe(path)

    def test_rejects_file_size_bounds_and_path_string_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            short = root / "short"
            short.write_bytes(b"x" * (observer.MIN_FILE_BYTES - 1))
            with self.assertRaises(JsonInputError):
                self._observe(short)

            oversized = root / "oversized"
            oversized.write_bytes(gguf())
            with patch.object(observer, "MAX_FILE_BYTES", oversized.stat().st_size - 1), self.assertRaises(JsonInputError):
                self._observe(oversized)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = observer.main(["x" * (observer.MAX_PATH_BYTES + 1)])
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertLessEqual(len(stderr.getvalue().encode("utf-8")), observer.MAX_ERROR_BYTES)

    def test_rejects_directory_and_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaises(JsonInputError):
                self._observe(root)
            target = root / "target"
            target.write_bytes(gguf())
            link = root / "link"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            with self.assertRaises(JsonInputError):
                self._observe(link)

    def test_nonblocking_open_rejects_nonregular_descriptor_and_closes_it(self) -> None:
        descriptor = 73
        nonblock = 1 << 20
        regular = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=11,
            st_ino=22,
            st_size=observer.MIN_FILE_BYTES,
            st_mtime_ns=33,
        )
        nonregular = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
        with (
            patch.object(observer.os, "O_NONBLOCK", nonblock, create=True),
            patch.object(observer.os, "lstat", return_value=regular) as lstat,
            patch.object(observer.os, "open", return_value=descriptor) as open_file,
            patch.object(observer.os, "fstat", return_value=nonregular) as fstat,
            patch.object(observer.os, "close") as close,
            self.assertRaisesRegex(JsonInputError, "regular file"),
        ):
            observer.observe_file("selected")

        lstat.assert_called_once_with("selected")
        open_file.assert_called_once()
        opened_path, flags = open_file.call_args.args
        self.assertEqual("selected", opened_path)
        self.assertEqual(nonblock, flags & nonblock)
        fstat.assert_called_once_with(descriptor)
        close.assert_called_once_with(descriptor)

    def test_detects_replacement_during_controlled_parser_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "model"
            path.write_bytes(gguf())
            original = observer.validate_gguf_fd

            def parse_then_replace(descriptor: int, **kwargs: object):
                evidence = original(descriptor, **kwargs)
                with path.open("ab") as handle:
                    handle.write(b"x")
                return evidence

            with patch.object(observer, "validate_gguf_fd", parse_then_replace), self.assertRaises(JsonInputError):
                self._observe(path)

    def test_observer_does_not_write_selected_file_or_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "model"
            body = gguf()
            path.write_bytes(body)
            before_entries = sorted(item.name for item in root.iterdir())
            before_bytes = path.read_bytes()
            self._observe(path)
            self.assertEqual(before_entries, sorted(item.name for item in root.iterdir()))
            self.assertEqual(before_bytes, path.read_bytes())

    def test_cli_success_is_canonical_and_failure_has_empty_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "model"
            path.write_bytes(gguf())
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = observer.main([str(path)])
            self.assertEqual(0, status)
            self.assertEqual("", stderr.getvalue())
            value = json.loads(stdout.getvalue())
            self.assertEqual("FILE_EVIDENCE_ONLY", value["result"])
            self.assertEqual(canonical_bytes(value).decode("ascii"), stdout.getvalue())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = observer.main([str(path), "extra"])
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertTrue(stderr.getvalue())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(observer, "MAX_OUTPUT_BYTES", 1),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                status = observer.main([str(path)])
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertTrue(stderr.getvalue())
            self.assertLessEqual(len(stderr.getvalue().encode("utf-8")), observer.MAX_ERROR_BYTES)


if __name__ == "__main__":
    unittest.main()
