"""Focused tests: entitlement scope, expiry/revocation, the HumanGate route and credentials."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.rights import (  # noqa: E402
    HIGH_RISK_ACTIONS, HumanGateBypassAttempt, HumanGateRoute, RightsDenied, RightsScope,
    assert_credential_scope, assert_human_gate_satisfied, check_rights, human_gate_route,
)

NOW = "2026-06-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"


class TestCheckRights(unittest.TestCase):
    def test_entitled_action_is_allowed(self):
        scope = RightsScope("svc-a", frozenset({"read"}))
        self.assertTrue(check_rights(scope, "read").allowed)

    def test_unknown_entitlement_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}))
        decision = check_rights(scope, "write")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "UNKNOWN_ENTITLEMENT_FAIL_CLOSED")

    def test_expired_scope_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}), expires_at=PAST)
        decision = check_rights(scope, "read", now=NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "EXPIRED")

    def test_revoked_scope_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}), revoked=True)
        self.assertEqual(check_rights(scope, "read").reason, "REVOKED")

    def test_none_expiry_never_means_expired(self):
        scope = RightsScope("svc-a", frozenset({"read"}), expires_at=None)
        self.assertTrue(check_rights(scope, "read", now=NOW).allowed)

    def test_malformed_expiry_fails_closed(self):
        scope = RightsScope("svc-a", frozenset({"read"}), expires_at="tomorrow")
        self.assertFalse(check_rights(scope, "read", now=NOW).allowed)

    def test_high_risk_entitlement_still_needs_gate(self):
        scope = RightsScope("svc-a", frozenset({"release"}))
        decision = check_rights(scope, "release", now=NOW)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_human_gate)

    def test_wrong_subject_is_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}))
        decision = check_rights(scope, "read", subject="svc-b")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "SUBJECT_MISMATCH")

    def test_unknown_scope_fails_closed(self):
        decision = check_rights(object(), "read")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "UNKNOWN_SCOPE_FAIL_CLOSED")


class TestHumanGateRoute(unittest.TestCase):
    def test_every_high_risk_action_is_gated(self):
        for action in sorted(HIGH_RISK_ACTIONS):
            with self.subTest(action=action):
                route = human_gate_route(action)
                self.assertTrue(route.required)
                self.assertEqual(route.route, "ARTIFACT:HUMAN_GATE")
                self.assertEqual(route.authority_edge, "HUMAN_GATE:%s" % action)

    def test_low_risk_action_is_ungated(self):
        route = human_gate_route("read")
        self.assertFalse(route.required)
        self.assertEqual(route.route, "NONE")

    def test_unknown_action_is_gated(self):
        self.assertTrue(human_gate_route("").required)


class TestHumanGateSatisfaction(unittest.TestCase):
    def test_missing_approval_ref_is_a_bypass_attempt(self):
        route = human_gate_route("release")
        with self.assertRaises(HumanGateBypassAttempt):
            assert_human_gate_satisfied(route, "")

    def test_none_approval_ref_is_a_bypass_attempt(self):
        route = human_gate_route("release")
        with self.assertRaises(HumanGateBypassAttempt):
            assert_human_gate_satisfied(route, None)

    def test_self_approval_is_a_bypass_attempt(self):
        route = human_gate_route("production_promotion")
        with self.assertRaises(HumanGateBypassAttempt):
            assert_human_gate_satisfied(route, "agent-7", requesting_actor="agent-7")

    def test_independent_approval_passes(self):
        route = human_gate_route("release")
        self.assertIsNone(assert_human_gate_satisfied(route, "HG-2026-0007",
                                                      requesting_actor="agent-7"))

    def test_ungated_route_needs_nothing(self):
        assert_human_gate_satisfied(human_gate_route("read"), "")

    def test_unknown_route_fails_closed(self):
        with self.assertRaises(HumanGateBypassAttempt):
            assert_human_gate_satisfied(object(), "HG-1")

    def test_code_is_stable(self):
        self.assertEqual(HumanGateBypassAttempt.code, "ERR_HUMAN_GATE_BYPASS_ATTEMPT")


class TestCredentialScope(unittest.TestCase):
    def test_out_of_scope_use_is_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"vault-read"}))
        with self.assertRaises(RightsDenied):
            assert_credential_scope(scope, "vault-write")

    def test_empty_credential_scope_permits_nothing(self):
        scope = RightsScope("svc-a", frozenset({"read"}))
        with self.assertRaises(RightsDenied):
            assert_credential_scope(scope, "vault-read")

    def test_in_scope_use_passes(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"vault-read"}))
        self.assertIsNone(assert_credential_scope(scope, "vault-read"))

    def test_revoked_scope_denies_credential_use(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"vault-read"}),
                            revoked=True)
        with self.assertRaises(RightsDenied):
            assert_credential_scope(scope, "vault-read")

    def test_wrong_subject_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"vault-read"}))
        with self.assertRaises(RightsDenied):
            assert_credential_scope(scope, "vault-read", subject="svc-b")

    def test_code_is_stable(self):
        self.assertEqual(RightsDenied.code, "ERR_RIGHTS_DENIED")

    def test_route_dataclass_is_frozen(self):
        route = human_gate_route("release")
        self.assertIsInstance(route, HumanGateRoute)


if __name__ == "__main__":
    unittest.main()
