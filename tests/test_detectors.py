from __future__ import annotations

import unittest
from dataclasses import dataclass

from lumi_eggcracker.detectors import load_bundled, load_catalogue, match
from lumi_eggcracker.jsonio import JsonInputError


@dataclass(frozen=True)
class Sample:
    exe_basename: str
    argv: tuple[str, ...]
    fd_paths: tuple[str, ...] = ()
    map_basenames: tuple[str, ...] = ()


class DetectorTests(unittest.TestCase):
    def test_llama_cpp_requires_model_argument(self) -> None:
        catalogue = load_bundled()
        self.assertIsNone(match(catalogue, Sample("llama-cli", ("/usr/bin/llama-cli", "--help"))))
        value = match(catalogue, Sample("llama-cli", ("/usr/bin/llama-cli", "-m", "/models/tiny.gguf")))
        self.assertEqual(("llama.cpp", ("exe_basename", "argv_model_suffix")), value)

    def test_generic_language_runtime_is_not_a_match(self) -> None:
        catalogue = load_bundled()
        self.assertIsNone(match(catalogue, Sample("python3", ("/usr/bin/python3", "worker.py", "--model", "cat"))))
        self.assertIsNone(match(catalogue, Sample("node", ("node", "agent.js"))))

    def test_catalogue_rejects_unknown_predicate(self) -> None:
        raw = b'{"schema_version":"lumi-eggcracker.detectors.v1","profiles":[{"id":"bad","all":[{"kind":"unknown","values":["x"]}]}]}'
        with self.assertRaises(JsonInputError):
            load_catalogue(raw)

    def test_catalogue_digest_is_exact(self) -> None:
        raw = b'{"schema_version":"lumi-eggcracker.detectors.v1","profiles":[{"id":"one","all":[{"kind":"exe_basename","values":["one"]}]}]}'
        with self.assertRaises(JsonInputError):
            load_catalogue(raw, expected_digest="0" * 64)
