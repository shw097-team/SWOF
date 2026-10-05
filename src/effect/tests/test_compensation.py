"""Focused tests: irreversibility detection, planned (never executed) compensation, no-path refusal."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from effect.compensation import (  # noqa: E402
    COMPENSABLE_KINDS, CompensationPointer, IrreversibleEffect, NoCompensationPath,
    assert_compensable, classify, plan_compensation,
)
from effect.substrate import intend  # noqa: E402


def as_state(record, state, reason_code=""):
    return record.__class__(**{**record.__dict__, "state": state, "reason_code": reason_code})


def partial():
    return as_state(intend("eff-1", "subj-1", {"op": "transfer"}), "PARTIAL_EFFECT",
                    "PARTIAL_EFFECT_DETECTED")


class TestClassify(unittest.TestCase):
    def test_declared_irreversible_attempt_classifies_irreversible(self):
        record = as_state(intend("eff-1", "subj-1", {"op": "send"}), "ATTEMPTED")
        self.assertEqual(classify(record, irreversible_attempts=("eff-1",)), "IRREVERSIBLE")

    def test_without_declaration_state_is_returned(self):
        record = partial()
        self.assertEqual(classify(record), "PARTIAL_EFFECT")

    def test_undeclared_attempt_is_not_irreversible(self):
        record = as_state(intend("eff-1", "subj-1", {"op": "send"}), "ATTEMPTED")
        self.assertEqual(classify(record, irreversible_attempts=("other-effect",)),
                         "ATTEMPTED")


class TestPlanCompensation(unittest.TestCase):
    def test_irreversible_is_not_compensable(self):
        record = as_state(intend("eff-1", "subj-1", {"op": "send"}), "ATTEMPTED")
        pointer = plan_compensation(record, irreversible_attempts=("eff-1",))
        self.assertIsInstance(pointer, CompensationPointer)
        self.assertFalse(pointer.compensable)
        self.assertEqual(pointer.reason_code, "IRREVERSIBLE_EFFECT")

    def test_partial_with_registered_path(self):
        registry = {"eff-1": {"kind": "ROLLBACK", "ref": "comp-0001"}}
        pointer = plan_compensation(partial(), registry=registry)
        self.assertTrue(pointer.compensable)
        self.assertIn(pointer.kind, COMPENSABLE_KINDS)
        self.assertEqual(pointer.ref, "comp-0001")
        self.assertEqual(pointer.target_effect_id, "eff-1")

    def test_partial_without_path_raises(self):
        with self.assertRaises(NoCompensationPath):
            plan_compensation(partial())
        self.assertEqual(NoCompensationPath.code, "ERR_NO_COMPENSATION_PATH")

    def test_non_partial_state_has_no_compensation_pointer(self):
        record = as_state(intend("eff-1", "subj-1", {"op": "create"}), "RECONCILED")
        pointer = plan_compensation(record)
        self.assertFalse(pointer.compensable)

    def test_registered_but_kindless_ref_raises(self):
        with self.assertRaises(NoCompensationPath):
            plan_compensation(partial(), registry={"eff-1": {"kind": "DELETE", "ref": "x"}})


class TestAssertCompensable(unittest.TestCase):
    def test_irreversible_pointer_raises(self):
        pointer = CompensationPointer("eff-1", "", "NONE", False, "IRREVERSIBLE_EFFECT")
        with self.assertRaises(IrreversibleEffect) as ctx:
            assert_compensable(pointer)
        self.assertEqual(IrreversibleEffect.code, "ERR_IRREVERSIBLE_EFFECT")

    def test_compensable_pointer_is_returned(self):
        pointer = CompensationPointer("eff-1", "comp-0001", "ROLLBACK", True,
                                      "COMPENSATION_PLANNED")
        self.assertIs(assert_compensable(pointer), pointer)

    def test_non_pointer_is_refused(self):
        with self.assertRaises(IrreversibleEffect):
            assert_compensable({"compensable": True})

    def test_no_path_pointer_raises_no_compensation_path(self):
        pointer = CompensationPointer("eff-1", "", "NONE", False, "NOT_PARTIAL_EFFECT")
        with self.assertRaises(NoCompensationPath):
            assert_compensable(pointer)

    def test_planning_never_executes(self):
        registry = {"eff-1": {"kind": "COMPENSATE", "ref": "comp-0002"}}
        pointer = plan_compensation(partial(), registry=registry)
        self.assertEqual(pointer.ref, "comp-0002")
        self.assertTrue(pointer.compensable)


if __name__ == "__main__":
    unittest.main()
