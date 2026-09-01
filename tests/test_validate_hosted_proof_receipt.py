from __future__ import annotations

import copy
import importlib.util
import json
import math
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from jsonschema import ValidationError
from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_hosted_proof_receipt.py"
SCHEMA = json.loads(
    (ROOT / "schemas" / "hosted-proof-receipt-v1.schema.json").read_text(encoding="utf-8")
)
SUCCESS = json.loads(
    (ROOT / "schemas" / "examples" / "hosted-proof-receipt-v1-success.json").read_text(
        encoding="utf-8"
    )
)

spec = importlib.util.spec_from_file_location("validate_hosted_proof_receipt", SCRIPT)
if spec is None or spec.loader is None:
    raise AssertionError("receipt validator script is not importable")
validator_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator_module)


class HostedProofReceiptValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        validator_class = validator_for(SCHEMA)
        validator_class.check_schema(SCHEMA)
        cls.reference = validator_class(SCHEMA)

    def test_current_success_and_failure_shapes_match_reference_validator(self) -> None:
        failure = {
            "mode": "containment-primitive-probe",
            "reason_code": "ROOT_REQUIRED",
            "result": "FAILED",
        }
        for receipt in (SUCCESS, failure):
            with self.subTest(receipt=receipt):
                self.reference.validate(receipt)
                validator_module.validate_receipt(receipt, SCHEMA)

    def test_invalid_shapes_match_reference_rejection(self) -> None:
        invalid_receipts = [
            {**SUCCESS, "detail": "private value"},
            {**SUCCESS, "target_processes": True},
            {**SUCCESS, "source_commit": "not-a-commit"},
            {
                "mode": "containment-primitive-probe",
                "reason_code": "UNKNOWN",
                "result": "FAILED",
            },
        ]
        for receipt in invalid_receipts:
            with (
                self.subTest(receipt=receipt),
                self.assertRaises(ValidationError),
            ):
                self.reference.validate(receipt)
            with self.subTest(receipt=receipt), self.assertRaises(
                validator_module.ReceiptValidationError
            ):
                validator_module.validate_receipt(receipt, SCHEMA)

    def test_nonfinite_number_is_rejected(self) -> None:
        receipt = {**SUCCESS, "trigger_to_empty_ms": math.nan}
        with self.assertRaisesRegex(
            validator_module.ReceiptValidationError,
            "exactly one v1 shape",
        ):
            validator_module.validate_receipt(receipt, SCHEMA)

    def test_integral_float_matches_reference_integer_semantics(self) -> None:
        receipt = {**SUCCESS, "descendant_cgroups_checked": 1.0}
        self.reference.validate(receipt)
        validator_module.validate_receipt(receipt, SCHEMA)

    def test_unknown_schema_keyword_in_either_branch_fails_closed(self) -> None:
        failure = {
            "mode": "containment-primitive-probe",
            "reason_code": "ROOT_REQUIRED",
            "result": "FAILED",
        }
        for receipt, opposite_branch in ((SUCCESS, 1), (failure, 0)):
            schema = copy.deepcopy(SCHEMA)
            schema["oneOf"][opposite_branch]["properties"]["mode"]["maxLength"] = 40
            with self.subTest(receipt=receipt), self.assertRaisesRegex(
                validator_module.ReceiptValidationError,
                "unsupported validation keyword",
            ):
                validator_module.validate_receipt(receipt, schema)

    def test_cli_accepts_synthetic_example_without_printing_contents(self) -> None:
        output = StringIO()
        error = StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = validator_module.main(
                [str(ROOT / "schemas" / "examples" / "hosted-proof-receipt-v1-success.json")]
            )
        self.assertEqual(0, status)
        self.assertEqual("VALID hosted-proof receipt v1\n", output.getvalue())
        self.assertEqual("", error.getvalue())

    def test_cli_rejects_duplicates_without_echoing_private_value(self) -> None:
        private_value = "do-not-echo-this"
        encoded = (
            '{"mode":"containment-primitive-probe","reason_code":"ROOT_REQUIRED",'
            f'"result":"FAILED","result":"{private_value}"}}'
        )
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(encoded, encoding="utf-8")
            output = StringIO()
            error = StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                status = validator_module.main([str(receipt)])
        self.assertEqual(1, status)
        self.assertEqual("", output.getvalue())
        self.assertIn("duplicate object member", error.getvalue())
        self.assertNotIn(private_value, error.getvalue())

    def test_cli_rejects_oversized_input_before_json_parsing(self) -> None:
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_bytes(b" " * (validator_module.MAX_RECEIPT_BYTES + 1))
            error = StringIO()
            with redirect_stderr(error):
                status = validator_module.main([str(receipt)])
        self.assertEqual(1, status)
        self.assertIn("safe size bound", error.getvalue())

    def test_cli_rejects_invalid_utf8_without_echoing_contents(self) -> None:
        private_value = "private-utf8-marker"
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_bytes(b"\xff" + private_value.encode("ascii"))
            error = StringIO()
            with redirect_stderr(error):
                status = validator_module.main([str(receipt)])
        self.assertEqual(1, status)
        self.assertIn("not bounded UTF-8 JSON", error.getvalue())
        self.assertNotIn(private_value, error.getvalue())

    def test_cli_rejects_nonfinite_json_without_echoing_contents(self) -> None:
        private_value = "private-number-marker"
        encoded = f'{{"value":NaN,"private":"{private_value}"}}'
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(encoded, encoding="utf-8")
            error = StringIO()
            with redirect_stderr(error):
                status = validator_module.main([str(receipt)])
        self.assertEqual(1, status)
        self.assertIn("non-standard number", error.getvalue())
        self.assertNotIn(private_value, error.getvalue())

    def test_cli_rejects_nonregular_input_without_echoing_path(self) -> None:
        private_value = "private-directory-marker"
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / private_value
            receipt.mkdir()
            error = StringIO()
            with redirect_stderr(error):
                status = validator_module.main([str(receipt)])
        self.assertEqual(1, status)
        self.assertIn("must be a regular file", error.getvalue())
        self.assertNotIn(private_value, error.getvalue())


if __name__ == "__main__":
    unittest.main()
