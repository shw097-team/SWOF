"""Adversarial tests: hostile payloads, secret smuggling and fail-closed refusal paths.

Every test here tries to make the substrate look safe when it is not: a secret hidden in a
nested list, in a dict KEY, in an unscannable object, an empty string offered as "nothing was
found", a caller forging the sequence or the event kind, and a derived span trying to become
another subject's evidence.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from observability.correlation import (  # noqa: E402
    CorrelationUnbound, derive, key, new_context,
)
from observability.hooks import HookBus, UnknownEventKind  # noqa: E402
from observability.redaction import LogUnsafe, assert_log_safe, redact_event, redact_line  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"


def ctx(subject_id="subj-1"):
    return new_context(workorder_id="WO-SWOF-W2-004", checkpoint_id="cp-1",
                       subject_id=subject_id, subject_sha="c" * 64, trace_id="trace-1")


class TestSecretSmuggling(unittest.TestCase):
    def test_secret_in_a_nested_list_is_removed(self):
        clean, receipt = redact_event({"rows": [["plain", "token %s" % AWS_KEY]]})
        self.assertNotIn(AWS_KEY, json.dumps(clean))
        self.assertFalse(receipt["safe"])

    def test_secret_in_a_dict_key_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_event({"key %s" % AWS_KEY: "value"})

    def test_unscannable_object_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_event({"blob": object()})

    def test_private_key_block_is_redacted(self):
        safe, receipt = redact_line("pem %s" % PRIVATE_KEY)
        self.assertNotIn("PRIVATE KEY", safe)
        self.assertEqual(receipt["redactions"]["SECRET"], 1)

    def test_bus_refuses_a_smuggled_payload_without_appending(self):
        bus = HookBus()
        with self.assertRaises(LogUnsafe):
            bus.emit("workorder_state", correlation=ctx(),
                     payload={"key %s" % AWS_KEY: "value"})
        self.assertEqual(bus.events(), ())

    def test_seq_is_not_consumed_by_a_refused_emit(self):
        bus = HookBus()
        with self.assertRaises(LogUnsafe):
            bus.emit("workorder_state", correlation=ctx(), payload={"blob": object()})
        self.assertEqual(bus.emit("trace_start", correlation=ctx()).seq, 1)


class TestGateCannotBeSatisfiedVacuously(unittest.TestCase):
    def test_empty_string_is_refused(self):
        with self.assertRaises(LogUnsafe):
            assert_log_safe("")

    def test_empty_dict_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_event({})

    def test_empty_list_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_event({"rows": []})

    def test_none_is_refused(self):
        with self.assertRaises(LogUnsafe):
            assert_log_safe(None)

    def test_a_redacted_secret_is_not_confused_with_a_raw_one(self):
        safe, _ = redact_line(AWS_KEY)
        self.assertIsNone(assert_log_safe(safe))


class TestForgedOrderingAndKind(unittest.TestCase):
    def test_caller_supplied_seq_is_rejected_by_signature(self):
        bus = HookBus()
        with self.assertRaises(TypeError):
            bus.emit("checkpoint", correlation=ctx(), seq=7)

    def test_empty_kind_is_unknown(self):
        bus = HookBus()
        with self.assertRaises(UnknownEventKind):
            bus.emit("", correlation=ctx())

    def test_case_variant_kind_is_unknown(self):
        bus = HookBus()
        with self.assertRaises(UnknownEventKind):
            bus.emit("Trace_Start", correlation=ctx())

    def test_unbound_correlation_cannot_emit(self):
        bus = HookBus()
        with self.assertRaises(CorrelationUnbound):
            bus.emit("checkpoint", correlation=None)
        self.assertEqual(bus.events(), ())


class TestDeriveCannotSubstituteSubjects(unittest.TestCase):
    def test_suffix_naming_another_subject_changes_nothing_but_the_trace(self):
        parent = ctx("subj-1")
        hostile = derive(parent, suffix="subj-2")
        self.assertEqual(hostile.subject_id, "subj-1")
        self.assertEqual(hostile.subject_sha, parent.subject_sha)
        self.assertNotEqual(hostile.trace_id, parent.trace_id)

    def test_blank_subject_cannot_be_introduced_by_derive(self):
        with self.assertRaises(CorrelationUnbound):
            derive(ctx(), suffix="")

    def test_context_is_frozen(self):
        context = ctx()
        with self.assertRaises(Exception):
            context.subject_id = "subj-2"


class TestFirstFailureIsEvidence(unittest.TestCase):
    def test_many_recoveries_do_not_erase_the_first_failure(self):
        bus = HookBus()
        bus.emit("first_failure", correlation=ctx(), payload={"invariant": "INV-1"})
        for _ in range(5):
            bus.emit("recovery", correlation=ctx(), payload={"recovery_action": "retry"})
        bus.emit("rollback", correlation=ctx(), payload={"to": "baseline"})
        self.assertEqual(bus.first_failure().payload["invariant"], "INV-1")
        self.assertEqual(bus.first_failure().seq, 1)

    def test_replay_of_a_hostile_payload_is_still_redacted(self):
        bus = HookBus()
        bus.emit("workorder_state", correlation=ctx(),
                 payload={"rows": [{"note": "key %s" % AWS_KEY}]})
        self.assertNotIn(AWS_KEY, json.dumps(bus.replay()))

    def test_key_differs_after_a_derive(self):
        parent = ctx()
        self.assertNotEqual(key(parent), key(derive(parent, suffix="child")))


if __name__ == "__main__":
    unittest.main()