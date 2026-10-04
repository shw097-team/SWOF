"""WO-SWOF-W2-R001 acceptance tests: rights currentness and exact-bound human approval.

Every case below is one of the forty-four probes named in the repair spec. The failing cases must
FAIL CLOSED with an exact code; the positive controls must PASS. Nothing here reads a wall clock:
currentness is always an explicit trusted `now`/`commit_time`.
"""
import base64
import hashlib
import hmac
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.humangate import (  # noqa: E402
    ApprovalDecision, ApprovalRequest, ApprovalToken, NonceLedger, VerificationContext,
    canonical_payload_bytes, verify_approval_token,
)
from security.rights import (  # noqa: E402
    HumanGateBypassAttempt, HumanGateRoute, RightsDenied, RightsScope,
    assert_credential_scope, assert_human_gate_satisfied, check_rights, currentness_required,
    human_gate_route,
)

NOW = "2026-06-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"
COMMIT = "2026-06-01T00:30:00Z"

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
        commit_time=COMMIT,
        trusted_key_registry=_honest_registry,
        nonce_ledger=NonceLedger(), max_reauth_age_seconds=3600,
    )
    fields.update(overrides)
    return VerificationContext(**fields)


def _verify(token_over=None, request_over=None, ctx_over=None):
    return verify_approval_token(
        _valid_token(**(token_over or {})),
        _release_request(**(request_over or {})),
        _release_ctx(**(ctx_over or {})),
    )


class TestRightsCurrentness(unittest.TestCase):
    def test_01_expired_entitlement_without_now_fails_closed(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=PAST)
        decision = check_rights(scope, "doc.read")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "CURRENTNESS_UNAVAILABLE_FAIL_CLOSED")

    def test_02_expired_entitlement_with_now_is_expired(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=PAST)
        decision = check_rights(scope, "doc.read", now=NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "EXPIRED")

    def test_03_now_equal_to_expiry_is_expired(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=NOW)
        decision = check_rights(scope, "doc.read", now=NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "EXPIRED")

    def test_04_malformed_now_fails_closed(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=FUTURE)
        decision = check_rights(scope, "doc.read", now="not-a-time")
        self.assertFalse(decision.allowed)

    def test_05_revoked_scope_is_revoked(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), revoked=True)
        decision = check_rights(scope, "doc.read")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "REVOKED")

    def test_06_no_expiry_scope_without_now_still_entitled(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=None)
        decision = check_rights(scope, "doc.read")
        self.assertTrue(decision.allowed)
        self.assertFalse(currentness_required(scope))

    def test_07_no_expiry_scope_with_now_still_entitled(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=None)
        self.assertTrue(check_rights(scope, "doc.read", now=NOW).allowed)

    def test_08_expired_credential_scope_without_now_fails_closed(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"api.call"}),
                            expires_at=PAST)
        with self.assertRaises(RightsDenied) as caught:
            assert_credential_scope(scope, "api.call")
        self.assertEqual(str(caught.exception), "CURRENTNESS_UNAVAILABLE_FAIL_CLOSED")

    def test_09_expired_credential_scope_with_now_is_expired(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"api.call"}),
                            expires_at=PAST)
        with self.assertRaises(RightsDenied) as caught:
            assert_credential_scope(scope, "api.call", now=NOW)
        self.assertEqual(str(caught.exception), "EXPIRED_CREDENTIAL_SCOPE")

    def test_10_live_credential_scope_with_now_passes(self):
        scope = RightsScope("svc-a", frozenset({"read"}), credential_scope=frozenset({"api.call"}),
                            expires_at=FUTURE)
        self.assertIsNone(assert_credential_scope(scope, "api.call", now=NOW))

    def test_11_live_entitlement_with_now_is_entitled(self):
        scope = RightsScope("svc-a", frozenset({"doc.read"}), expires_at=FUTURE)
        self.assertTrue(check_rights(scope, "doc.read", now=NOW).allowed)


class TestHumanGateExactBoundApproval(unittest.TestCase):
    def _seam(self, approval, **kwargs):
        route = human_gate_route("release")
        return assert_human_gate_satisfied(route, approval, **kwargs)

    def test_12_bare_string_approved_is_refused(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam("approved")
        self.assertEqual(str(caught.exception), "NOT_A_CANONICAL_APPROVAL_TOKEN")

    def test_13_bare_string_sure_go_ahead_is_refused(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam("sure go ahead")
        self.assertEqual(str(caught.exception), "NOT_A_CANONICAL_APPROVAL_TOKEN")

    def test_14_bare_string_with_unrelated_actor_is_refused(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam("sure go ahead", requesting_actor="bob")
        self.assertEqual(str(caught.exception), "NOT_A_CANONICAL_APPROVAL_TOKEN")

    def test_15_wrong_subject_hash_is_denied(self):
        decision = _verify(token_over={"subject_hash": "b" * 64})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_16_wrong_operation_is_denied(self):
        decision = _verify(token_over={"operation": "delete"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_17_broader_resource_set_is_denied(self):
        decision = _verify(token_over={"resource": ("artifact:app", "artifact:extra")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_18_broader_scope_set_is_denied(self):
        decision = _verify(token_over={"scope": ("release", "extra")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_19_wrong_environment_is_denied(self):
        decision = _verify(token_over={"environment": "staging"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_20_wrong_data_class_is_denied(self):
        decision = _verify(token_over={"data_class": "SECRET"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_21_expired_token_is_denied(self):
        decision = _verify(token_over={"expires_at": "2026-06-01T00:00:00Z"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_TIME"))

    def test_22_not_yet_issued_token_is_denied(self):
        decision = _verify(token_over={"issued_at": "2026-06-01T01:00:00Z"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_TIME"))

    def test_23_commit_time_equal_to_expiry_is_denied(self):
        decision = _verify(token_over={"expires_at": COMMIT})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_TIME"))

    def test_24_non_active_token_state_is_denied(self):
        for state in ("REVOKED", "CONSUMED", "EXPIRED"):
            with self.subTest(state=state):
                decision = _verify(token_over={"token_state": state})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_STATE"))

    def test_25_stale_authn_session_generation_is_denied(self):
        decision = _verify(ctx_over={"authn_session_generation": 99})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))

    def test_26_stale_credential_generation_is_denied(self):
        decision = _verify(ctx_over={"credential_generation": 99})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))

    def test_27_stale_rights_security_provider_ruin_consent_generation_is_denied(self):
        for name in ("rights_generation", "security_policy_generation", "provider_generation",
                     "ruin_generation", "consent_generation"):
            with self.subTest(generation=name):
                decision = _verify(ctx_over={name: 1})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))

    def test_28_non_human_approver_is_false_authority(self):
        for approver in ("model:gpt", "tool:router", "provider:cloud", "agent:bot",
                         "mcp:server", "a2a:peer", "automation:job"):
            with self.subTest(approver=approver):
                decision = _verify(token_over={"approver": approver})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_FALSE_AUTHORITY"))

    def test_29_self_issued_approval_is_refused(self):
        # The verifier has no knowledge of the requester, so self-issue is refused at the seam:
        # the approver equal to the requesting actor is a SELF_APPROVAL_REFUSED bypass attempt.
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(_valid_token(), requesting_actor="human:carol",
                       request=_release_request(), ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "SELF_APPROVAL_REFUSED")

    def test_30_stale_reauthentication_is_denied(self):
        decision = _verify(token_over={"reauthenticated_at": "2026-05-01T00:00:00Z"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))

    def test_31_non_canonical_authn_assurance_class_is_denied(self):
        decision = _verify(token_over={"authn_assurance_class": "AAC9"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))

    def test_32_missing_rollback_ref_for_p3_is_denied(self):
        decision = _verify(request_over={"effect_risk_tier": "P3", "permission_class": "P3",
                                            "rollback_ref": ""})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_NO_ROLLBACK"))

    def test_33_consumer_audience_mismatch_is_denied(self):
        decision = _verify(ctx_over={"expected_consumer_audience_hash": "b" * 64})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUDIENCE_MISMATCH"))

    def test_34_no_trusted_key_registry_is_denied(self):
        decision = _verify(ctx_over={"trusted_key_registry": None})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_35_unregistered_key_or_wrong_generation_is_denied(self):
        unregistered = _verify(ctx_over={"trusted_key_registry": lambda i, k, g: False})
        self.assertEqual((unregistered.ok, unregistered.code), (False, "DENY_TOKEN_INTEGRITY"))
        wrong_generation = _verify(ctx_over={"key_generation": 99})
        self.assertEqual((wrong_generation.ok, wrong_generation.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_36_replayed_nonce_is_denied(self):
        ledger = NonceLedger()
        first = _verify(ctx_over={"nonce_ledger": ledger})
        self.assertTrue(first.ok)
        second = _verify(ctx_over={"nonce_ledger": ledger})
        self.assertEqual((second.ok, second.code), (False, "DENY_REPLAY"))

    def test_37_t3_without_independent_checker_evidence_is_denied(self):
        decision = _verify(request_over={"autonomy_tier": "T3"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_T3_CHECKER"))

    def test_38_t3_with_mismatched_checker_evidence_is_denied(self):
        decision = _verify(
            token_over={"independent_checker_required": True,
                        "independent_checker_evidence_ref": "evidence:one"},
            request_over={"autonomy_tier": "T3"},
            ctx_over={"independent_checker_evidence_ref": "evidence:two"},
        )
        self.assertEqual((decision.ok, decision.code), (False, "DENY_T3_CHECKER"))

    def test_39_bad_signature_or_digest_shape_is_denied(self):
        bad_signature = _verify(token_over={"signature": "short"})
        self.assertEqual((bad_signature.ok, bad_signature.code), (False, "DENY_TOKEN_SCHEMA"))
        bad_digest = _verify(token_over={"subject_hash": "not-a-digest"})
        self.assertEqual((bad_digest.ok, bad_digest.code), (False, "DENY_TOKEN_SCHEMA"))

    def test_40_wrong_integrity_profile_id_is_denied(self):
        decision = _verify(token_over={"integrity_profile_id": "SWOF-HG-INTEGRITY-999"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_SCHEMA"))


class TestHumanGatePositiveControls(unittest.TestCase):
    def test_41_valid_exact_bound_t2_p2_token_is_approved(self):
        decision = _verify()
        self.assertTrue(decision.ok)
        self.assertEqual(decision.code, "APPROVE_BASIS_SATISFIED")
        route = human_gate_route("release")
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave",
            request=_release_request(), ctx=_release_ctx()))

    def test_42_consume_once_seam_passes_first_and_ledger_rejects_second(self):
        ledger = NonceLedger()
        route = human_gate_route("release")
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave",
            request=_release_request(), ctx=_release_ctx(nonce_ledger=ledger)))
        second = _verify(ctx_over={"nonce_ledger": ledger})
        self.assertEqual((second.ok, second.code), (False, "DENY_REPLAY"))

    def test_43_valid_t3_token_with_matching_checker_evidence_is_approved(self):
        decision = _verify(
            token_over={"independent_checker_required": True,
                        "independent_checker_evidence_ref": "evidence:one"},
            request_over={"autonomy_tier": "T3"},
            ctx_over={"independent_checker_evidence_ref": "evidence:one"},
        )
        self.assertTrue(decision.ok)
        self.assertEqual(decision.code, "APPROVE_BASIS_SATISFIED")

    def test_44_nonce_ledger_rejects_empty_or_non_string_nonce(self):
        ledger = NonceLedger()
        self.assertFalse(ledger.reserve(""))
        self.assertFalse(ledger.reserve("   "))
        self.assertFalse(ledger.reserve(None))
        self.assertFalse(ledger.reserve(12345))
        self.assertTrue(ledger.reserve("nonce-x"))
        self.assertFalse(ledger.reserve("nonce-x"))




class TestSignatureDelegationR2(unittest.TestCase):
    """BLK-1: the injected registry is a real VERIFIER over canonical_payload_bytes."""

    def test_r2_01_forged_signature_passes_only_with_a_contract_violating_stub(self):
        # DOCUMENTATION TEST (BLK-1 failure mode). The signature below is 86-char shape-valid but
        # does NOT correspond to the token payload. A registry that returns True WITHOUT consulting
        # payload_bytes is NOT a valid verifier: the library defers to it and accepts the forgery.
        # That is the integrator's contract violation, encoded here so it can never pass silently.
        forged = _valid_token(signature=SIGNATURE)
        self.assertEqual(len(forged.signature), 86)
        stub = lambda payload, signature, issuer_id, key_id, key_generation: True
        with_stub = verify_approval_token(
            forged, _release_request(), _release_ctx(trusted_key_registry=stub))
        self.assertEqual((with_stub.ok, with_stub.code), (True, "APPROVE_BASIS_SATISFIED"))
        # Proof the library never verified anything itself: the honest registry refuses it.
        honest = verify_approval_token(forged, _release_request(), _release_ctx())
        self.assertEqual((honest.ok, honest.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r2_02_honest_registry_verifies_a_matching_token(self):
        decision = _verify()
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r2_03_honest_registry_rejects_a_tampered_payload(self):
        signed = _valid_token()
        # The signature was computed over subject_hash="a"*64; change it after signing. The exact
        # binding still holds (token == request), so only integrity can catch this.
        tampered = replace(signed, subject_hash="b" * 64)
        request = _release_request(subject_hash="b" * 64)
        decision = verify_approval_token(tampered, request, _release_ctx())
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r2_04_honest_registry_rejects_wrong_key_generation(self):
        decision = _verify(token_over={"key_generation": 99})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r2_05_non_true_or_failing_registry_is_denied(self):
        def _raiser(*args):
            raise RuntimeError("registry unavailable")

        cases = {
            "none": lambda *args: None,
            "false": lambda *args: False,
            "one_is_not_true": lambda *args: 1,
            "raises": _raiser,
            "wrong_arity": lambda payload, signature: True,
        }
        for name, registry in cases.items():
            with self.subTest(registry=name):
                decision = _verify(ctx_over={"trusted_key_registry": registry})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r2_06_absent_registry_is_denied(self):
        decision = _verify(ctx_over={"trusted_key_registry": None})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r2_07_approver_equal_to_actor_is_false_authority(self):
        decision = _verify(token_over={"approver": "human:alice"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_FALSE_AUTHORITY"))

    def test_r2_13_canonical_payload_is_deterministic_and_field_sensitive(self):
        first = canonical_payload_bytes(_valid_token())
        second = canonical_payload_bytes(_valid_token())
        self.assertEqual(first, second)
        self.assertNotEqual(first, canonical_payload_bytes(_valid_token(nonce="nonce-2")))
        body = json.loads(first.decode("utf-8"))
        self.assertNotIn("signature", body)
        self.assertEqual(canonical_payload_bytes(_valid_token(signature="A" * 86)),
                         canonical_payload_bytes(_valid_token(signature="B" * 86)))


class TestRouteReDerivationR2(unittest.TestCase):
    """BLK-3 / NB-1: the route is re-derived, never trusted, and P3 surfaces TOK-INV-001."""

    def test_r2_08_understated_route_for_a_high_risk_action_is_refused(self):
        route = HumanGateRoute(False, "NONE", "NONE")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=_release_request(), ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "ROUTE_UNDERSTATES_ACTION")

    def test_r2_09_underivable_route_without_a_request_fails_closed(self):
        route = HumanGateRoute(False, "NONE", "NONE")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", requesting_actor="human:alice")
        self.assertEqual(str(caught.exception), "ROUTE_NOT_REDERIVABLE_FAIL_CLOSED")

    def test_r2_10_agreed_low_risk_route_returns_none(self):
        route = human_gate_route("read")
        request = _release_request(operation="read")
        self.assertIsNone(assert_human_gate_satisfied(route, "", request=request))

    def test_r2_11_p3_request_with_bare_string_approval_needs_a_typed_token(self):
        route = human_gate_route("release")
        request = _release_request(effect_risk_tier="P3", permission_class="P3")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "HG-2026-0007", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r2_12_p3_request_with_a_valid_typed_token_passes(self):
        route = human_gate_route("release")
        request = _release_request(effect_risk_tier="P3", permission_class="P3")
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request,
            ctx=_release_ctx()))


if __name__ == "__main__":
    unittest.main()