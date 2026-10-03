"""Focused tests: deny by default, explicit deny beats allow, no self-service widening."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.permissions import (  # noqa: E402
    Decision, HumanGateRequired, PermissionDenied, PermissionEnvelope,
    PermissionExpansionRefused, UnknownPermissionTarget, assert_authorized, authorize,
    effective_actions, widen,
)


def envelope(**overrides):
    fields = {
        "subject": "svc-a",
        "allowed_actions": frozenset({"read", "write", "release"}),
        "denied_actions": frozenset({"write"}),
        "human_gate_actions": frozenset({"release"}),
        "default": "DENY",
    }
    fields.update(overrides)
    return PermissionEnvelope(**fields)


class TestDenyByDefault(unittest.TestCase):
    def test_explicit_deny_beats_allow(self):
        decision = authorize(envelope(), "write")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "DENIED_EXPLICIT")

    def test_deny_wins_regardless_of_set_order(self):
        forward = envelope(allowed_actions=frozenset({"a", "b"}), denied_actions=frozenset({"b"}),
                           human_gate_actions=frozenset())
        reverse = envelope(allowed_actions=frozenset({"b"}), denied_actions=frozenset({"a", "b"}),
                           human_gate_actions=frozenset())
        self.assertEqual(authorize(forward, "b").reason_code, "DENIED_EXPLICIT")
        self.assertEqual(authorize(reverse, "b").reason_code, "DENIED_EXPLICIT")

    def test_unknown_action_fails_closed(self):
        decision = authorize(envelope(), "undeclared")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "UNKNOWN_ACTION_FAIL_CLOSED")

    def test_default_allow_still_denies_unknown_action(self):
        decision = authorize(envelope(default="ALLOW"), "undeclared")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "UNKNOWN_ACTION_FAIL_CLOSED")

    def test_allowed_action_is_allowed(self):
        decision = authorize(envelope(), "read")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "ALLOWED_BY_ENVELOPE")
        self.assertFalse(decision.requires_human_gate)


class TestHumanGate(unittest.TestCase):
    def test_human_gate_action_is_never_directly_usable(self):
        decision = authorize(envelope(), "release")
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_human_gate)
        self.assertEqual(decision.reason_code, "HUMAN_GATE_REQUIRED")

    def test_assert_authorized_raises_human_gate_required(self):
        with self.assertRaises(HumanGateRequired) as ctx:
            assert_authorized(envelope(), "release")
        self.assertEqual(HumanGateRequired.code, "ERR_HUMAN_GATE_REQUIRED")
        self.assertIn("release", str(ctx.exception))

    def test_assert_authorized_raises_permission_denied(self):
        with self.assertRaises(PermissionDenied):
            assert_authorized(envelope(), "write")

    def test_assert_authorized_returns_decision_when_allowed(self):
        decision = assert_authorized(envelope(), "read")
        self.assertIsInstance(decision, Decision)
        self.assertTrue(decision.allowed)


class TestWidening(unittest.TestCase):
    def test_widen_of_non_admitted_action_is_refused(self):
        with self.assertRaises(PermissionExpansionRefused):
            widen(envelope(), "undeclared")

    def test_widen_of_denied_action_is_refused(self):
        with self.assertRaises(PermissionExpansionRefused):
            widen(envelope(), "write")

    def test_widen_of_human_gated_action_is_refused(self):
        with self.assertRaises(PermissionExpansionRefused):
            widen(envelope(), "release")

    def test_widen_of_admitted_action_returns_envelope_unchanged(self):
        env = envelope()
        self.assertEqual(widen(env, "read").allowed_actions, env.allowed_actions)

    def test_effective_actions_excludes_denied_and_gated(self):
        self.assertEqual(effective_actions(envelope()), frozenset({"read"}))


class TestUnknownTargets(unittest.TestCase):
    def test_empty_subject_is_refused(self):
        with self.assertRaises(UnknownPermissionTarget):
            authorize(envelope(subject=""), "read")

    def test_non_frozenset_collection_is_refused(self):
        with self.assertRaises(UnknownPermissionTarget):
            authorize(envelope(allowed_actions={"read"}), "read")

    def test_non_string_action_is_refused(self):
        with self.assertRaises(UnknownPermissionTarget):
            authorize(envelope(), 123)

    def test_empty_action_string_is_refused(self):
        with self.assertRaises(UnknownPermissionTarget):
            authorize(envelope(), "")

    def test_unknown_permission_target_code(self):
        self.assertEqual(UnknownPermissionTarget.code, "ERR_UNKNOWN_PERMISSION_TARGET")
        self.assertEqual(PermissionExpansionRefused.code, "ERR_PERMISSION_EXPANSION_REFUSED")

    def test_subject_binding_denies_other_subject(self):
        decision = authorize(envelope(), "read", context={"subject": "svc-b"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "SUBJECT_MISMATCH")


if __name__ == "__main__":
    unittest.main()
