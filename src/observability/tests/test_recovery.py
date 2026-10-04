"""Focused tests: no implicit recovery path, rollback binding, first failing invariant and a
deterministic readback that is a pure function of the events."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from observability.correlation import CorrelationContext  # noqa: E402
from observability.correlation import new_context  # noqa: E402
from observability.hooks import HookBus  # noqa: E402
from observability.recovery import (  # noqa: E402
    NoRecoveryPath, deterministic_readback, first_failing_invariant, recovery_plan,
    rollback_pointer,
)

SHA = "b" * 64


def ctx(subject_id="subj-1"):
    return new_context(workorder_id="WO-SWOF-W2-004", checkpoint_id="cp-1",
                       subject_id=subject_id, subject_sha=SHA, trace_id="trace-1")


def failing_bus(failure_kind="PERMISSION_DENIED", invariant="INV-1"):
    bus = HookBus()
    bus.emit("trace_start", correlation=ctx(), payload={"op": "begin"})
    bus.emit("first_failure", correlation=ctx(),
             payload={"failure_kind": failure_kind, "invariant": invariant})
    bus.emit("recovery", correlation=ctx(), payload={"recovery_action": "rollback"})
    return bus


class TestRollbackPointer(unittest.TestCase):
    def test_pointer_carries_workorder_and_baseline(self):
        pointer = rollback_pointer(workorder_id="WO-SWOF-W2-004", baseline_sha=SHA)
        self.assertEqual(pointer["workorder_id"], "WO-SWOF-W2-004")
        self.assertEqual(pointer["baseline_sha"], SHA)
        self.assertEqual(pointer["schema"], "SWOF-ROLLBACK-POINTER/1")

    def test_empty_workorder_is_refused(self):
        with self.assertRaises(ValueError):
            rollback_pointer(workorder_id="", baseline_sha=SHA)

    def test_empty_baseline_is_refused(self):
        with self.assertRaises(ValueError):
            rollback_pointer(workorder_id="WO-SWOF-W2-004", baseline_sha="")


class TestRecoveryPlan(unittest.TestCase):
    def test_registered_kind_maps_to_action(self):
        plan = recovery_plan(failure_event=failing_bus().first_failure(),
                             registry={"PERMISSION_DENIED": "rollback"})
        self.assertEqual(plan["failure_kind"], "PERMISSION_DENIED")
        self.assertEqual(plan["recovery_action"], "rollback")

    def test_unmapped_kind_raises_no_recovery_path(self):
        with self.assertRaises(NoRecoveryPath) as caught:
            recovery_plan(failure_event=failing_bus("UNMAPPED").first_failure(),
                          registry={"PERMISSION_DENIED": "rollback"})
        self.assertEqual(caught.exception.failure_kind, "UNMAPPED")
        self.assertEqual(NoRecoveryPath.code, "ERR_NO_RECOVERY_PATH")

    def test_plan_always_carries_the_rollback_pointer(self):
        plan = recovery_plan(failure_event=failing_bus().first_failure(),
                             registry={"PERMISSION_DENIED": "rollback"})
        self.assertIn("rollback_pointer", plan)
        self.assertEqual(plan["rollback_pointer"]["workorder_id"], "WO-SWOF-W2-004")
        self.assertEqual(plan["rollback_pointer"]["baseline_sha"], SHA)

    def test_plan_carries_the_failing_checkpoint_and_seq(self):
        event = failing_bus().first_failure()
        plan = recovery_plan(failure_event=event, registry={"PERMISSION_DENIED": "rollback"})
        self.assertEqual(plan["checkpoint_id"], "cp-1")
        self.assertEqual(plan["seq"], event.seq)

    def test_non_failure_event_is_refused(self):
        bus = HookBus()
        event = bus.emit("checkpoint", correlation=ctx())
        with self.assertRaises(ValueError):
            recovery_plan(failure_event=event, registry={"PERMISSION_DENIED": "rollback"})

    def test_registry_must_be_a_mapping(self):
        with self.assertRaises(ValueError):
            recovery_plan(failure_event=failing_bus().first_failure(), registry=["nope"])

    def test_plan_accepts_a_plain_mapping_failure_event(self):
        event = {
            "seq": 1,
            "kind": "first_failure",
            "correlation": CorrelationContext("t", "WO-SWOF-W2-004", "cp-1", "subj-1", SHA),
            "payload": {"failure_kind": "K"},
        }
        plan = recovery_plan(failure_event=event, registry={"K": "rollback"})
        self.assertEqual(plan["recovery_action"], "rollback")
        self.assertEqual(plan["rollback_pointer"]["baseline_sha"], SHA)


class TestFirstFailingInvariant(unittest.TestCase):
    def test_returns_the_earliest_failure_invariant(self):
        bus = HookBus()
        bus.emit("first_failure", correlation=ctx(), payload={"invariant": "INV-A"})
        bus.emit("first_failure", correlation=ctx(), payload={"invariant": "INV-B"})
        self.assertEqual(first_failing_invariant(bus.events()), "INV-A")

    def test_returns_none_when_no_failure_exists(self):
        bus = HookBus()
        bus.emit("trace_start", correlation=ctx())
        self.assertIsNone(first_failing_invariant(bus.events()))

    def test_returns_none_for_an_empty_stream(self):
        self.assertIsNone(first_failing_invariant([]))

    def test_is_order_independent(self):
        events = list(failing_bus(invariant="INV-1").events())
        self.assertEqual(first_failing_invariant(list(reversed(events))), "INV-1")


class TestDeterministicReadback(unittest.TestCase):
    def test_same_events_yield_identical_bytes(self):
        events = failing_bus().events()
        self.assertEqual(json.dumps(deterministic_readback(events)),
                         json.dumps(deterministic_readback(events)))

    def test_readback_is_order_normalised(self):
        events = list(failing_bus().events())
        self.assertEqual(deterministic_readback(list(reversed(events))),
                         deterministic_readback(events))

    def test_readback_rows_carry_the_signature_keys(self):
        rows = deterministic_readback(failing_bus().events())
        expected = {"seq", "kind", "trace_id", "workorder_id", "checkpoint_id", "subject_id",
                    "subject_sha", "invariant", "recovery_action"}
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(set(row), expected)

    def test_readback_is_a_pure_function(self):
        events = list(failing_bus().events())
        before = json.dumps(deterministic_readback(events))
        deterministic_readback(events)
        self.assertEqual(json.dumps(deterministic_readback(events)), before)

    def test_empty_stream_reads_back_empty(self):
        self.assertEqual(deterministic_readback([]), [])


if __name__ == "__main__":
    unittest.main()