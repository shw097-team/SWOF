"""Focused tests: entitlement scope, expiry/revocation, the HumanGate route and credentials.

WO-SWOF-W2-R001: the HumanGate tests that previously treated a bare string reference as a
satisfying approval now encode the exact-bound law - a gated route requires a typed, verified,
exact-bound ApprovalToken. Coverage is not reduced: each former case is either refuted with the
new code or exercised through a real token.
"""
import base64
import hashlib
import hmac
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.humangate import (  # noqa: E402
    ApprovalRequest, ApprovalToken, NonceLedger, VerificationContext, canonical_payload_bytes,
)
from security.rights import (  # noqa: E402
    HIGH_RISK_ACTIONS, HumanGateBypassAttempt, HumanGateRoute, RightsDenied, RightsScope,
    assert_credential_scope, assert_human_gate_satisfied, check_rights, human_gate_route,
)

NOW = "2026-06-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"

DIGEST = "a" * 64
SIGNATURE = "A" * 86

DIGEST = "a" * 64
SIGNATURE = "A" * 86

# WO-SWOF-W2-R002: the injected registry is a real VERIFIER over canonical_payload_bytes. These
# test helpers build an honest HMAC verifier so a matching token verifies and a tampered one does
# not. _TEST_KEY never leaves this test module; the library itself performs no cryptography.
_TEST_KEY = b"swof-w2-r002-hmac-test-key"


def _sign_payload(payload: bytes) -> str:
    """HMAC-SHA512 over the canonical bytes, rendered as the 86-char base64url token shape.

    SHA512 yields a 64-byte digest whose base64url encoding is exactly 86 characters - the shape
    the ApprovalToken schema requires. This is a TEST verifier; the library does no crypto.
    """
    digest = hmac.new(_TEST_KEY, payload, hashlib.sha512).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _honest_registry(payload, signature, issuer_id, key_id, key_generation):
    """A contract-correct verifier: recompute over payload_bytes and return a strict bool."""
    if (issuer_id, key_id, key_generation) != ("issuer-1", "key-1", 3):
        return False
    return hmac.compare_digest(_sign_payload(payload), signature)


def _valid_token(**overrides):
    fields = dict(
        token_id="tok-1", request_id="req-1", decision_id="dec-1", subject="svc-a",
        subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice", operation="release",
        target_system="swof", resource=("artifact:app",), environment="prod",
        purpose_ref="purpose:release", scope=("release",), data_class="INTERNAL",
        effect_digest=DIGEST, consumer_audience_hash=DIGEST, approver="human:carol",
        authority_class="HUMAN_OPERATOR", approver_authn_context_ref="authn:ctx-1",
        authn_assurance_class="AAC2", reauthenticated_at="2026-06-01T00:00:00Z",
        authn_session_generation=7, credential_generation=8, approval_basis_hash=DIGEST,
        independent_checker_required=False, independent_checker_evidence_ref="",
        issued_at="2026-06-01T00:00:00Z", expires_at="2026-06-01T01:00:00Z", nonce="nonce-1",
        rollback_ref="rollback:1", token_state="ACTIVE", consumer="swof",
        integrity_profile_id="SWOF-HG-INTEGRITY-001", issuer_id="issuer-1", key_id="key-1",
        key_generation=3, signature=SIGNATURE,
    )
    fields.update(overrides)
    token = ApprovalToken(**fields)
    if "signature" in overrides:
        return token
    return replace(token, signature=_sign_payload(canonical_payload_bytes(token)))


def _release_request(**overrides):
    fields = dict(
        subject="svc-a", subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice",
        operation="release", target_system="swof", resource=("artifact:app",), environment="prod",
        purpose_ref="purpose:release", scope=("release",), data_class="INTERNAL",
        effect_digest=DIGEST, consumer_audience_hash=DIGEST, effect_risk_tier="P2",
        permission_class="P2", autonomy_tier="T2", required_authority="HUMAN_GATE:release",
        rollback_ref="rollback:1", independent_checker_required=False,
    )
    fields.update(overrides)
    return ApprovalRequest(**fields)


def _release_ctx(**overrides):
    fields = dict(
        commit_time="2026-06-01T00:30:00Z",
        trusted_key_registry=_honest_registry,
        nonce_ledger=NonceLedger(), max_reauth_age_seconds=3600,
    )
    fields.update(overrides)
    return VerificationContext(**fields)


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

    def test_expiring_scope_without_now_fails_closed(self):
        scope = RightsScope("svc-a", frozenset({"read"}), expires_at=PAST)
        decision = check_rights(scope, "read")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "CURRENTNESS_UNAVAILABLE_FAIL_CLOSED")

    def test_revoked_scope_denied(self):
        scope = RightsScope("svc-a", frozenset({"read"}), revoked=True)
        self.assertEqual(check_rights(scope, "read").reason, "REVOKED")

    def test_none_expiry_never_means_expired(self):
        scope = RightsScope("svc-a", frozenset({"read"}), expires_at=None)
        self.assertTrue(check_rights(scope, "read", now=NOW).allowed)
        self.assertTrue(check_rights(scope, "read").allowed)

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

    def test_self_issued_string_is_no_longer_an_approval(self):
        route = human_gate_route("production_promotion")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "agent-7", requesting_actor="agent-7")
        self.assertIn("NOT_A_CANONICAL_APPROVAL_TOKEN", str(caught.exception))

    def test_syntactic_string_is_no_longer_an_approval(self):
        route = human_gate_route("release")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "HG-2026-0007", requesting_actor="human:alice")
        self.assertIn("NOT_A_CANONICAL_APPROVAL_TOKEN", str(caught.exception))

    def test_verified_exact_bound_token_passes(self):
        route = human_gate_route("release")
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:alice",
            request=_release_request(), ctx=_release_ctx()))

    def test_ungated_route_is_honoured_only_when_rederivation_agrees(self):
        request = _release_request(operation="read")
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_route("read"), "", request=request))

    def test_ungated_route_without_a_request_fails_closed(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(human_gate_route("read"), "")
        self.assertEqual(str(caught.exception), "ROUTE_NOT_REDERIVABLE_FAIL_CLOSED")

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