"""Focused tests: the five-part correlation identity and the derive substitution law."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from observability.correlation import (  # noqa: E402
    CorrelationContext, CorrelationUnbound, assert_bound, derive, key, new_context,
)

SHA = "a" * 64


def ctx(**overrides):
    base = dict(workorder_id="WO-SWOF-W2-004", checkpoint_id="cp-1", subject_id="subj-1",
                subject_sha=SHA, trace_id="trace-1")
    base.update(overrides)
    return new_context(**base)


class TestNewContext(unittest.TestCase):
    def test_binds_every_field(self):
        c = ctx()
        self.assertEqual(c.trace_id, "trace-1")
        self.assertEqual(c.workorder_id, "WO-SWOF-W2-004")
        self.assertEqual(c.checkpoint_id, "cp-1")
        self.assertEqual(c.subject_id, "subj-1")
        self.assertEqual(c.subject_sha, SHA)

    def test_trace_id_is_derived_when_absent(self):
        c = new_context(workorder_id="wo", checkpoint_id="cp", subject_id="s", subject_sha=SHA)
        self.assertTrue(c.trace_id)
        self.assertEqual(c.trace_id,
                         new_context(workorder_id="wo", checkpoint_id="cp", subject_id="s",
                                     subject_sha=SHA).trace_id)

    def test_blank_field_is_refused(self):
        with self.assertRaises(CorrelationUnbound) as caught:
            ctx(checkpoint_id="")
        self.assertEqual(caught.exception.field, "checkpoint_id")
        self.assertEqual(CorrelationUnbound.code, "ERR_CORRELATION_UNBOUND")

    def test_whitespace_only_field_is_refused(self):
        with self.assertRaises(CorrelationUnbound):
            ctx(subject_id="   ")

    def test_non_string_field_is_refused(self):
        with self.assertRaises(CorrelationUnbound):
            ctx(subject_sha=12345)

    def test_none_trace_is_seeded_not_an_error(self):
        c = new_context(workorder_id="wo", checkpoint_id="cp", subject_id="s", subject_sha=SHA,
                        trace_id=None)
        self.assertTrue(c.trace_id)


class TestAssertBound(unittest.TestCase):
    def test_bound_context_is_returned(self):
        c = ctx()
        self.assertIs(assert_bound(c), c)

    def test_structurally_incomplete_context_is_refused(self):
        broken = CorrelationContext(trace_id="t", workorder_id="wo", checkpoint_id="",
                                    subject_id="s", subject_sha=SHA)
        with self.assertRaises(CorrelationUnbound):
            assert_bound(broken)

    def test_non_context_is_refused(self):
        with self.assertRaises(CorrelationUnbound):
            assert_bound({"trace_id": "t"})


class TestDerive(unittest.TestCase):
    def test_derive_keeps_subject_identity(self):
        child = derive(ctx(), suffix="child")
        self.assertEqual(child.subject_id, "subj-1")
        self.assertEqual(child.subject_sha, SHA)
        self.assertEqual(child.workorder_id, "WO-SWOF-W2-004")
        self.assertEqual(child.checkpoint_id, "cp-1")

    def test_derive_moves_only_the_trace(self):
        parent = ctx()
        child = derive(parent, suffix="child")
        self.assertEqual(child.trace_id, "trace-1.child")
        self.assertNotEqual(key(child), key(parent))

    def test_derive_refuses_a_blank_suffix(self):
        with self.assertRaises(CorrelationUnbound):
            derive(ctx(), suffix="")

    def test_derive_cannot_re_point_the_subject(self):
        parent = ctx()
        child = derive(parent, suffix="subj-2")
        self.assertEqual(child.subject_id, parent.subject_id)
        self.assertEqual(child.subject_sha, parent.subject_sha)


class TestKey(unittest.TestCase):
    def test_key_is_stable_and_hex(self):
        value = key(ctx())
        self.assertEqual(value, key(ctx()))
        self.assertEqual(len(value), 64)
        int(value, 16)

    def test_key_depends_on_every_field(self):
        base = ctx()
        variants = [
            ctx(trace_id="trace-2"),
            ctx(workorder_id="WO-OTHER"),
            ctx(checkpoint_id="cp-2"),
            ctx(subject_id="subj-2"),
            ctx(subject_sha="b" * 64),
        ]
        for variant in variants:
            self.assertNotEqual(key(base), key(variant))

    def test_key_refuses_an_unbound_context(self):
        with self.assertRaises(CorrelationUnbound):
            key(CorrelationContext("t", "wo", "", "s", SHA))


if __name__ == "__main__":
    unittest.main()