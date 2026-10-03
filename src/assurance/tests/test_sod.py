"""Tests: maker != checker, an always-refusing product write, and the checker receipt."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from assurance.sod import (  # noqa: E402
    CheckerWriteRefused, ReadOnlyChecker, SoDViolation, assert_separated,
)


class TestAssertSeparated(unittest.TestCase):
    def test_separated_identities_return_receipt(self):
        receipt = assert_separated("producer-1", "checker-1")
        self.assertEqual(receipt["schema"], "SWOF-SOD-RECEIPT/1")
        self.assertTrue(receipt["separated"])
        self.assertEqual(receipt["producer"], "producer-1")
        self.assertEqual(receipt["checker"], "checker-1")

    def test_maker_as_checker_raises(self):
        with self.assertRaises(SoDViolation) as ctx:
            assert_separated("same", "same")
        self.assertEqual(SoDViolation.code, "ERR_SOD_VIOLATION")
        self.assertEqual(ctx.exception.reason_code, "SOD_SAME_IDENTITY")

    def test_empty_identity_raises(self):
        with self.assertRaises(SoDViolation) as ctx:
            assert_separated("", "checker-1")
        self.assertEqual(ctx.exception.reason_code, "SOD_EMPTY_IDENTITY")

    def test_non_independent_receipt_is_recorded(self):
        self.assertFalse(assert_separated("p", "c", independent=False)["independent"])


class TestReadOnlyChecker(unittest.TestCase):
    def test_empty_checker_id_is_refused(self):
        with self.assertRaises(SoDViolation):
            ReadOnlyChecker("")

    def test_identity_is_exposed(self):
        self.assertEqual(ReadOnlyChecker("checker-1").identity, "checker-1")

    def test_product_write_always_refused(self):
        checker = ReadOnlyChecker("checker-1")
        with self.assertRaises(CheckerWriteRefused) as ctx:
            checker.write_product("src/assurance/predicate.py", b"tampered")
        self.assertEqual(CheckerWriteRefused.code, "ERR_CHECKER_WRITE_REFUSED")
        self.assertEqual(ctx.exception.reason_code, "CHECKER_MAY_NOT_WRITE_PRODUCT")

    def test_candidate_file_unchanged_after_refused_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate.py"
            candidate.write_bytes(b"frozen candidate")
            checker = ReadOnlyChecker("checker-1", allowed_evidence_root=str(Path(tmp) / "ev"))
            with self.assertRaises(CheckerWriteRefused):
                checker.write_product(str(candidate), b"repaired by the checker")
            self.assertEqual(candidate.read_bytes(), b"frozen candidate")

    def test_evidence_write_outside_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = ReadOnlyChecker("checker-1", allowed_evidence_root=str(Path(tmp) / "ev"))
            with self.assertRaises(CheckerWriteRefused) as ctx:
                checker.write_evidence(str(Path(tmp) / "elsewhere" / "e.json"), b"{}")
            self.assertEqual(ctx.exception.reason_code, "EVIDENCE_OUTSIDE_ALLOWED_ROOT")

    def test_evidence_write_inside_root_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ev"
            checker = ReadOnlyChecker("checker-1", allowed_evidence_root=str(root))
            result = checker.write_evidence(str(root / "receipt.json"), b"{}")
            self.assertTrue(result["allowed"])

    def test_receipt_records_reads_and_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp) / "ev")
            checker = ReadOnlyChecker("checker-1", allowed_evidence_root=root)
            checker.read("src/assurance/predicate.py")
            with self.assertRaises(CheckerWriteRefused):
                checker.write_product("src/assurance/predicate.py", b"x")
            with self.assertRaises(CheckerWriteRefused):
                checker.write_evidence(str(Path(tmp) / "outside.json"), b"x")
            receipt = checker.record()
            self.assertEqual(receipt["reads"], ("src/assurance/predicate.py",))
            self.assertEqual(len(receipt["refused_writes"]), 2)
            targets = sorted(w["target"] for w in receipt["refused_writes"])
            self.assertEqual(targets, ["EVIDENCE", "PRODUCT"])


if __name__ == "__main__":
    unittest.main()