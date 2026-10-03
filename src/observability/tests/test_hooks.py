"""Focused tests: fail-closed kinds, bus-assigned seq, redaction-before-storage, first-failure
retention, byte-stable replay and a sink that only ever sees redacted lines."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from observability.correlation import new_context  # noqa: E402
from observability.hooks import (  # noqa: E402
    EVENT_KINDS, Event, HookBus, UnknownEventKind,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def ctx(subject_id="subj-1"):
    return new_context(workorder_id="WO-SWOF-W2-004", checkpoint_id="cp-1",
                       subject_id=subject_id, subject_sha="a" * 64, trace_id="trace-1")


class TestVocabulary(unittest.TestCase):
    def test_closed_vocabulary(self):
        self.assertEqual(
            EVENT_KINDS,
            frozenset({"trace_start", "workorder_state", "checkpoint", "first_failure",
                       "recovery", "rollback", "evidence_invalidation", "subject_bound"}))

    def test_unknown_kind_raises(self):
        bus = HookBus()
        with self.assertRaises(UnknownEventKind) as caught:
            bus.emit("not_a_kind", correlation=ctx())
        self.assertEqual(caught.exception.kind, "not_a_kind")
        self.assertEqual(UnknownEventKind.code, "ERR_UNKNOWN_EVENT_KIND")

    def test_unknown_kind_does_not_append(self):
        bus = HookBus()
        with self.assertRaises(UnknownEventKind):
            bus.emit("nope", correlation=ctx())
        self.assertEqual(bus.events(), ())


class TestSeq(unittest.TestCase):
    def test_seq_is_contiguous_from_one(self):
        bus = HookBus()
        for kind in ("trace_start", "checkpoint", "first_failure"):
            bus.emit(kind, correlation=ctx())
        self.assertEqual([e.seq for e in bus.events()], [1, 2, 3])

    def test_caller_cannot_choose_seq(self):
        bus = HookBus()
        with self.assertRaises(TypeError):
            bus.emit("checkpoint", correlation=ctx(), seq=99)
        self.assertEqual(bus.emit("checkpoint", correlation=ctx()).seq, 1)

    def test_unbound_correlation_is_refused(self):
        bus = HookBus()
        with self.assertRaises(Exception):
            bus.emit("checkpoint", correlation=None)
        self.assertEqual(bus.events(), ())

    def test_payload_must_be_a_mapping(self):
        bus = HookBus()
        with self.assertRaises(ValueError):
            bus.emit("checkpoint", correlation=ctx(), payload=["not", "a", "mapping"])

    def test_emitted_at_is_echoed(self):
        bus = HookBus()
        event = bus.emit("checkpoint", correlation=ctx(), emitted_at="2026-01-01T00:00:00Z")
        self.assertEqual(event.emitted_at, "2026-01-01T00:00:00Z")


class TestRedactionBeforeStorage(unittest.TestCase):
    def test_secret_never_enters_the_stream(self):
        bus = HookBus()
        event = bus.emit("workorder_state", correlation=ctx(),
                         payload={"note": "key %s" % AWS_KEY})
        self.assertNotIn(AWS_KEY, json.dumps(event.payload))
        self.assertIn("_redaction", event.payload)
        self.assertFalse(event.payload["_redaction"]["safe"])

    def test_receipt_reports_what_was_removed(self):
        bus = HookBus()
        event = bus.emit("checkpoint", correlation=ctx(),
                         payload={"note": "key %s" % AWS_KEY})
        self.assertGreaterEqual(event.payload["_redaction"]["redactions"]["SECRET"], 1)

    def test_clean_payload_records_a_clean_receipt(self):
        bus = HookBus()
        event = bus.emit("checkpoint", correlation=ctx(), payload={"note": "plain"})
        self.assertTrue(event.payload["_redaction"]["safe"])


class TestSink(unittest.TestCase):
    def test_sink_receives_only_redacted_lines(self):
        seen = []
        bus = HookBus(sink=seen.append)
        bus.emit("workorder_state", correlation=ctx(), payload={"note": "key %s" % AWS_KEY})
        self.assertEqual(len(seen), 1)
        self.assertNotIn(AWS_KEY, seen[0])
        self.assertIn("[REDACTED:SECRET]", seen[0])

    def test_sink_line_is_json(self):
        seen = []
        bus = HookBus(sink=seen.append)
        bus.emit("trace_start", correlation=ctx(), payload={"op": "begin"})
        self.assertEqual(json.loads(seen[0])["kind"], "trace_start")

    def test_non_callable_sink_is_refused(self):
        with self.assertRaises(ValueError):
            HookBus(sink="console")


class TestFirstFailureRetention(unittest.TestCase):
    def test_first_failure_is_not_erased_by_recovery(self):
        bus = HookBus()
        first = bus.emit("first_failure", correlation=ctx(),
                         payload={"invariant": "INV-FIRST", "failure_kind": "K"})
        bus.emit("recovery", correlation=ctx(), payload={"recovery_action": "rollback"})
        bus.emit("rollback", correlation=ctx(), payload={"to": "baseline"})
        self.assertEqual(bus.first_failure().seq, first.seq)
        self.assertEqual(bus.first_failure().payload["invariant"], "INV-FIRST")

    def test_first_failure_is_absent_before_any_failure(self):
        bus = HookBus()
        bus.emit("trace_start", correlation=ctx())
        self.assertIsNone(bus.first_failure())

    def test_later_failure_does_not_replace_the_first(self):
        bus = HookBus()
        bus.emit("first_failure", correlation=ctx(), payload={"invariant": "INV-A"})
        bus.emit("first_failure", correlation=ctx(), payload={"invariant": "INV-B"})
        self.assertEqual(bus.first_failure().payload["invariant"], "INV-A")


class TestReplay(unittest.TestCase):
    def make_bus(self):
        bus = HookBus()
        bus.emit("trace_start", correlation=ctx(), payload={"op": "begin"})
        bus.emit("subject_bound", correlation=ctx(), payload={"subject_id": "subj-1"})
        bus.emit("first_failure", correlation=ctx(), payload={"invariant": "INV-X"})
        bus.emit("evidence_invalidation", correlation=ctx(), payload={"reason": "stale"})
        return bus

    def test_replay_is_byte_stable_across_two_calls(self):
        bus = self.make_bus()
        first = json.dumps(bus.replay(), sort_keys=True)
        second = json.dumps(bus.replay(), sort_keys=True)
        self.assertEqual(first, second)

    def test_replay_is_ordered_by_seq(self):
        bus = self.make_bus()
        self.assertEqual([row["seq"] for row in bus.replay()], [1, 2, 3, 4])

    def test_replay_rows_carry_the_required_keys(self):
        bus = self.make_bus()
        expected = {"seq", "kind", "trace_id", "workorder_id", "checkpoint_id", "subject_id",
                    "payload"}
        for row in bus.replay():
            self.assertEqual(set(row), expected)

    def test_replay_is_deterministic_regardless_of_query_time(self):
        bus = self.make_bus()
        snapshot = bus.replay()
        bus.emit("checkpoint", correlation=ctx())
        self.assertEqual(bus.replay()[:4], snapshot)

    def test_replay_carries_redacted_payloads(self):
        bus = HookBus()
        bus.emit("workorder_state", correlation=ctx(), payload={"note": "key %s" % AWS_KEY})
        self.assertNotIn(AWS_KEY, json.dumps(bus.replay()))


class TestTally(unittest.TestCase):
    def test_tally_counts_per_kind(self):
        bus = HookBus()
        bus.emit("checkpoint", correlation=ctx())
        bus.emit("checkpoint", correlation=ctx())
        bus.emit("recovery", correlation=ctx())
        self.assertEqual(bus.tally(), {"checkpoint": 2, "recovery": 1})

    def test_tally_is_empty_on_a_fresh_bus(self):
        self.assertEqual(HookBus().tally(), {})

    def test_events_are_immutable(self):
        bus = HookBus()
        event = bus.emit("checkpoint", correlation=ctx())
        self.assertIsInstance(event, Event)
        with self.assertRaises(Exception):
            event.seq = 999


if __name__ == "__main__":
    unittest.main()