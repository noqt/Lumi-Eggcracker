from __future__ import annotations

import unittest
from dataclasses import dataclass

from lumi_eggcracker.detectors import DetectionMatch, load_bundled, load_catalogue, match
from lumi_eggcracker.jsonio import JsonInputError


@dataclass(frozen=True)
class Sample:
    exe_basename: str
    argv: tuple[str, ...]
    fd_paths: tuple[str, ...] = ()
    map_basenames: tuple[str, ...] = ()


class DetectorTests(unittest.TestCase):
    def test_llama_cpp_fast_path_requires_model_argument(self) -> None:
        catalogue = load_bundled()
        self.assertIsNone(match(catalogue, Sample("llama-cli", ("/usr/bin/llama-cli", "--help"))))
        value = match(
            catalogue, Sample("llama-cli", ("/usr/bin/llama-cli", "-m", "/models/tiny.gguf"))
        )
        self.assertEqual(
            DetectionMatch("llama.cpp", "FAST_NAME", ("exe_basename", "argv_model_suffix")), value
        )

    def test_content_profile_requires_both_independent_groups(self) -> None:
        catalogue = load_bundled()
        sample = Sample("unfamiliar", ("anything",))
        self.assertIsNone(match(catalogue, sample, evidence={"MODEL_CONTENT": {"gguf-v3"}}))
        self.assertIsNone(match(catalogue, sample, evidence={"INFERENCE_RUNTIME": {"llama-elf"}}))
        self.assertEqual(
            DetectionMatch("content.gguf-llama", "CONTENT", ("gguf-v3", "llama-elf")),
            match(
                catalogue,
                sample,
                evidence={"MODEL_CONTENT": {"gguf-v3"}, "INFERENCE_RUNTIME": {"llama-elf"}},
            ),
        )

    def test_generic_language_runtime_is_not_a_match(self) -> None:
        catalogue = load_bundled()
        self.assertIsNone(
            match(catalogue, Sample("python3", ("/usr/bin/python3", "worker.py", "--model", "cat")))
        )
        self.assertIsNone(match(catalogue, Sample("node", ("node", "agent.js"))))

    def test_catalogue_rejects_unknown_predicate_and_incomplete_content_group(self) -> None:
        unknown = b'{"schema_version":"lumi-eggcracker.detectors.v2","profiles":[{"id":"bad","path":"FAST_NAME","all":[{"kind":"unknown","values":["x"]}]}]}'
        incomplete = b'{"schema_version":"lumi-eggcracker.detectors.v2","profiles":[{"id":"bad","path":"CONTENT","require_all_groups":[{"group":"MODEL_CONTENT","any":["gguf-v3"]}]}]}'
        for raw in (unknown, incomplete):
            with self.assertRaises(JsonInputError):
                load_catalogue(raw)

    def test_catalogue_digest_is_exact(self) -> None:
        raw = b'{"schema_version":"lumi-eggcracker.detectors.v2","profiles":[{"id":"one","path":"FAST_NAME","all":[{"kind":"exe_basename","values":["one"]}]}]}'
        with self.assertRaises(JsonInputError):
            load_catalogue(raw, expected_digest="0" * 64)
