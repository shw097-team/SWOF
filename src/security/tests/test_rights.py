"""Focused tests: entitlement scope, expiry/revocation, the HumanGate route and credentials.

WO-SWOF-W2-R001: the HumanGate tests that previously treated a bare string reference as a
satisfying approval now encode the exact-bound law - a gated route requires a typed, verified,
exact-bound ApprovalToken. Coverage is not reduced: each former case is either refuted with the
new code or exercised through a real token.
"""
import base64
import sys
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.humangate import (  # noqa: E402
    ApprovalRequest, ApprovalToken, HumanGateDecision, NonceLedger, VerificationContext,
    approval_basis_hash, approval_decision_basis_hash, canonical_payload_bytes,
    verify_approval_token,
)
from security.rights import (  # noqa: E402
    EFFECT_RISK_TIERS, HIGH_RISK_ACTIONS, HumanGateBypassAttempt, HumanGateRoute, NONE_ROUTE,
    RUIN_HARD_VETO_ROUTE, RUIN_SAFE_STOP_ROUTE, RightsDenied, RightsScope,
    assert_credential_scope, assert_human_gate_satisfied, check_rights, human_gate_required,
    human_gate_route,
)

NOW = "2026-06-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"

DIGEST = "a" * 64
SIGNATURE = "A" * 86

BASIS = approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0")
# WO-SWOF-W2-R007: the LITERAL frozen 15.5 approval basis for the fixture request, whose
# `decision_basis_hash` is R007_DECISION_BASIS. Source-derived, not helper-derived.
R007_FIXTURE_APPROVAL_BASIS = (
    "3c8dfb2d5ac6c678053550795acf87223d8b8df15816c4b5357aa990278b2c80"
)

# WO-SWOF-W2-R007 / R8: the LITERAL frozen ApprovalDecisionBasisV1 JCS digest (same fixture as the
# currentness suite) for the R8 generic gated request, whose resolved decision authority_class is
# HA1 (the PI06 clause anchor). An independent source constant, not a call to the helper under test.
R007_DECISION_BASIS = "9adf0095a78dd6244d3a9190b022ac611b0f73a7730b760fb352678da0c7b3c1"


def _authority_policy(decision_authority_class, required_authority):
    """TEST owner policy: only the exact HA class the request declares is sufficient."""
    return decision_authority_class == required_authority


def _current_decision(**overrides):
    fields = dict(
        decision_id="dec-1", request_id="req-1", decision="APPROVE", approver="human:carol",
        authority_class="HA1", authn_assurance_class="AAC2", reason_codes=("HG-RULE-001",),
        decided_at="2026-06-01T00:15:00Z", evidence_ref="evidence:decision-1",
        integrity_ref="integrity:decision-1", revoked=False, superseded=False,
    )
    fields.update(overrides)
    decision = HumanGateDecision(**fields)
    if "decision_basis_hash" in overrides:
        return decision
    return replace(decision, decision_basis_hash=R007_DECISION_BASIS)


def _decision_registry(mapping=None):
    decisions = dict(mapping or {"dec-1": _current_decision()})
    return lambda decision_id: decisions.get(decision_id)


def _request_resolver(trusted):
    """R6: the owner-callable trusted CURRENT request resolver, keyed by request_id (else None)."""
    return lambda request_id: trusted if trusted.request_id == request_id else None

# WO-SWOF-W2-R004: the signature is a REAL Ed25519 signature. The TEST key never leaves this
# module; the library performs the verification against a public key resolved by the registered
# resolver, and only the resolver supplies key material.
_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_PUBLIC_BYTES = _PRIVATE_KEY.public_key().public_bytes_raw()


def _sign_payload(payload: bytes) -> str:
    """Ed25519 over the canonical bytes, base64url WITHOUT padding -> exactly 86 characters."""
    return base64.urlsafe_b64encode(_PRIVATE_KEY.sign(payload)).decode("ascii").rstrip("=")


def _honest_registry(issuer_id, key_id, key_generation):
    """A contract-correct key RESOLVER: returns the raw Ed25519 public key bytes for the key."""
    if (issuer_id, key_id, key_generation) != ("issuer-1", "key-1", 3):
        return None
    return _PUBLIC_BYTES


def _valid_token(**overrides):
    fields = dict(
        token_id="tok-1", request_id="req-1", decision_id="dec-1", subject="svc-a",
        subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice",
        operation="ACT-EXTERNAL-WRITE-REV",
        target_system="swof", resource=("artifact:app",), environment="prod",
        purpose_ref="purpose:release", scope=("release",), data_class="INTERNAL",
        effect_digest=DIGEST, consumer_audience_hash=DIGEST, approver="human:carol",
        authority_class="HUMAN_OPERATOR", approver_authn_context_ref="authn:ctx-1",
        authn_assurance_class="AAC2", reauthenticated_at="2026-06-01T00:00:00Z",
        authn_session_generation=7, credential_generation=8,
        approval_basis_hash=R007_FIXTURE_APPROVAL_BASIS,
        if06b_version="1.0", payload_schema_version="1.0.0", min_reader_version="1.0",
        writer_version="DOC03-r2", compatibility_class="STRICT_MAJOR_ADDITIVE_MINOR",
        evidence_link="evidence:approval-basis-1",
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
    """R8: the canonical-valid GENERIC mechanics request (ACT-EXTERNAL-WRITE-REV / MEDIUM / P3 / HA1).

    It is a real gated request that MEETS the frozen PI06 minimum policy (P3 / MEDIUM / clause {HA1}
    / AAC1), so JCS / Ed25519 / time / nonce / generation / basis / lineage cases exercise the
    mechanics without being shadowed by the floor. The name is retained for history; RELEASE-specific
    cases use `_canonical_release_request` below.
    """
    fields = dict(
        subject="svc-a", subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice",
        operation="ACT-EXTERNAL-WRITE-REV", target_system="swof", resource=("artifact:app",),
        environment="prod", purpose_ref="purpose:release", scope=("release",), data_class="INTERNAL",
        effect_digest=DIGEST, consumer_audience_hash=DIGEST, effect_risk_tier="MEDIUM",
        permission_class="P3", autonomy_tier="T2", required_authority="HA1",
        required_authn_assurance="AAC2", adapter_kind="canonical",
        rollback_ref="rollback:1", independent_checker_required=False, ruin_class="NONE",
        request_id="req-1", decision_id="dec-1", decision_basis_hash=R007_DECISION_BASIS,
        generation_bundle_digest=DIGEST, rollback_digest=DIGEST,
    )
    fields.update(overrides)
    return ApprovalRequest(**fields)


def _canonical_release_request(**overrides):
    """R8: the canonical-valid RELEASE request (P5 / CRITICAL / T3 / HA1 + coapproval HA5 / AAC3)."""
    fields = dict(
        operation="release", effect_risk_tier="CRITICAL", permission_class="P5", autonomy_tier="T3",
        required_authority="HA1", required_coapprovals=("HA5",), required_authn_assurance="AAC3",
        independent_checker_required=True, effect_digest=DIGEST, consumer_audience_hash=DIGEST,
        generation_bundle_digest=DIGEST, rollback_digest=DIGEST,
    )
    fields.update(overrides)
    return _release_request(**fields)


def _release_token(**overrides):
    """R8: a canonical-valid RELEASE token binding the canonical release request."""
    fields = dict(
        operation="release", authn_assurance_class="AAC3", independent_checker_required=True,
        independent_checker_evidence_ref="evidence:checker-1", rollback_ref="rollback:1",
    )
    fields.update(overrides)
    return _valid_token(**fields)


def _release_ctx(**overrides):
    fields = dict(
        commit_time="2026-06-01T00:30:00Z",
        expected_consumer_audience_hash=DIGEST,
        trusted_key_registry=_honest_registry,
        nonce_ledger=NonceLedger(), max_reauth_age_seconds=3600,
        decision_resolver=_decision_registry(), authority_policy=_authority_policy,
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
        request = _release_request()
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:alice",
            request=request, ctx=_release_ctx(request_resolver=_request_resolver(request))))

    def test_ungated_route_is_honoured_only_when_rederivation_agrees(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        # R7: a benign NONE route now needs the TRUSTED current request to resolve.
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_route("read"), "", request=request,
            ctx=_release_ctx(request_resolver=_request_resolver(request))))

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


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R004 (R4): ONE canonical gate predicate, ruin precedence, and the real-Ed25519 seam.
# ---------------------------------------------------------------------------------------------
class TestCanonicalGatePredicateR4(unittest.TestCase):

    def test_p3_benign_operation_requires_a_token(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P3")
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertEqual(route.route, "ARTIFACT:HUMAN_GATE")
        self.assertEqual(route.authority_edge, "HUMAN_GATE:risk_tier")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "HG-2026-0001", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_permission_class_alone_gates_a_benign_operation(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P5")
        self.assertTrue(human_gate_required(request).required)

    def test_p2_benign_operation_is_ungated(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        self.assertEqual(human_gate_required(request).route, "NONE")

    def test_high_risk_operation_identifies_its_authority_edge(self):
        request = _release_request(operation="production_promotion")
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertEqual(route.authority_edge, "HUMAN_GATE:production_promotion")

    def test_gated_route_with_valid_token_passes(self):
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3")
        route = human_gate_required(request)
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:alice", request=request,
            ctx=_release_ctx(request_resolver=_request_resolver(request))))


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R007: the gated seam must carry the decision/authority lineage and FAIL CLOSED when
# no canonical current decision is resolvable - a signature is never a proxy for authority.
# ---------------------------------------------------------------------------------------------
class TestGatedAuthorityLineageR007(unittest.TestCase):

    def _seam(self, ctx):
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3")
        route = human_gate_required(request)
        # R6: inject the matching trusted current request so these lineage cases still exercise the
        # decision/authority seam rather than the (separately covered) trusted-request boundary.
        ctx = replace(ctx, request_resolver=_request_resolver(request))
        return assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request, ctx=ctx)

    def test_gated_route_without_a_resolvable_decision_fails_closed(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(_release_ctx(decision_resolver=None))
        self.assertEqual(str(caught.exception), "DENY_DECISION_UNRESOLVED")

    def test_gated_route_with_insufficient_authority_fails_closed(self):
        resolver = _decision_registry({"dec-1": _current_decision(authority_class="HA2")})
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(_release_ctx(decision_resolver=resolver))
        self.assertEqual(str(caught.exception), "DENY_INSUFFICIENT_AUTHORITY")

    def test_gated_route_with_absent_authority_policy_is_temp_closed(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(_release_ctx(authority_policy=None))
        self.assertEqual(str(caught.exception), "TEMP_CLOSED_AUTHORITY_RESOLUTION")

    def test_gated_route_with_current_decision_and_authority_passes(self):
        self.assertIsNone(self._seam(_release_ctx()))


class TestRuinPrecedenceR4(unittest.TestCase):

    def test_ruin_route_and_veto(self):
        request = _release_request(effect_risk_tier="RUIN")
        route = human_gate_required(request)
        self.assertEqual((route.required, route.route), (True, RUIN_HARD_VETO_ROUTE))
        self.assertEqual(route.authority_edge, "RUIN:HARD_VETO")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_valid_token_cannot_override_ruin(self):
        request = _release_request(effect_risk_tier="RUIN")
        route = human_gate_required(request)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                route, _valid_token(), requesting_actor="human:alice", request=request,
                ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_unknown_ruin_route_and_safe_stop(self):
        request = _release_request(effect_risk_tier="UNKNOWN_RUIN")
        route = human_gate_required(request)
        self.assertEqual((route.required, route.route), (True, RUIN_SAFE_STOP_ROUTE))
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                route, _valid_token(), requesting_actor="human:alice", request=request,
                ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")


class TestRealEd25519SeamR4(unittest.TestCase):

    def test_unknown_key_is_refused(self):
        forged = _valid_token(signature=SIGNATURE)
        request = _release_request()
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                human_gate_route("release"), forged, requesting_actor="human:alice",
                request=request, ctx=_release_ctx(request_resolver=_request_resolver(request)))
        self.assertEqual(str(caught.exception), "DENY_TOKEN_INTEGRITY")

    def test_real_signature_passes(self):
        request = _release_request()
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_route("release"), _valid_token(), requesting_actor="human:alice",
            request=request, ctx=_release_ctx(request_resolver=_request_resolver(request))))


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R005 (R5): canonical EffectRiskTier domain, ruin precedence from the canonical field,
# fail-closed enums, and the ONE canonical predicate. The CANONICAL enum is the authority here; no
# test may redefine it.
# ---------------------------------------------------------------------------------------------
class TestCanonicalRuinAndRiskTierR5(unittest.TestCase):

    def _seam(self, request, approval="", **kwargs):
        return assert_human_gate_satisfied(
            human_gate_required(request), approval, request=request, **kwargs)

    def test_canonical_effect_risk_tier_domain_is_exact(self):
        self.assertEqual(EFFECT_RISK_TIERS,
                         ("LOW", "MEDIUM", "HIGH", "CRITICAL", "RUIN", "UNKNOWN_RUIN"))

    def test_ruin_and_unknown_ruin_are_carried_by_effect_risk_tier(self):
        self.assertEqual(human_gate_required(_release_request(effect_risk_tier="RUIN")).route,
                         RUIN_HARD_VETO_ROUTE)
        self.assertEqual(
            human_gate_required(_release_request(effect_risk_tier="UNKNOWN_RUIN")).route,
            RUIN_SAFE_STOP_ROUTE)

    def test_ruin_with_valid_token_is_hard_veto(self):
        request = _release_request(effect_risk_tier="RUIN")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request, _valid_token(), requesting_actor="human:dave",
                       ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_ruin_without_token_is_hard_veto_not_token_required(self):
        request = _release_request(effect_risk_tier="RUIN")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_unknown_ruin_with_valid_token_is_safe_stop(self):
        request = _release_request(effect_risk_tier="UNKNOWN_RUIN")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request, _valid_token(), requesting_actor="human:dave",
                       ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_critical_and_high_are_risk_gated_canonically(self):
        for tier in ("CRITICAL", "HIGH"):
            with self.subTest(tier=tier):
                request = _release_request(operation="read", effect_risk_tier=tier,
                                           permission_class="P2")
                route = human_gate_required(request)
                self.assertTrue(route.required)
                self.assertEqual(route.route, "ARTIFACT:HUMAN_GATE")
                with self.assertRaises(HumanGateBypassAttempt) as caught:
                    self._seam(request)
                self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_low_and_medium_are_the_low_risk_positive_control(self):
        for tier in ("LOW", "MEDIUM"):
            with self.subTest(tier=tier):
                request = _release_request(operation="read", effect_risk_tier=tier,
                                           permission_class="P2")
                self.assertFalse(human_gate_required(request).required)
                # R7: the benign return requires the matching TRUSTED current request.
                self.assertIsNone(self._seam(
                    request, ctx=_release_ctx(request_resolver=_request_resolver(request))))

    def test_malformed_permission_class_fails_closed_not_ungated(self):
        for bad in ("p3", "P3 ", " P3", "", "P9"):
            with self.subTest(permission_class=bad):
                request = _release_request(operation="read", effect_risk_tier="LOW",
                                           permission_class=bad)
                self.assertTrue(human_gate_required(request).required)
                with self.assertRaises(HumanGateBypassAttempt):
                    self._seam(request)

    def test_malformed_effect_risk_tier_fails_closed_not_ungated(self):
        for bad in ("p3", "ruin", ""):
            with self.subTest(effect_risk_tier=bad):
                request = _release_request(operation="read", effect_risk_tier=bad,
                                           permission_class="P2")
                self.assertTrue(human_gate_required(request).required)
                with self.assertRaises(HumanGateBypassAttempt):
                    self._seam(request)

    def test_t3_benign_operation_requires_a_token(self):
        request = _release_request(operation="read", effect_risk_tier="LOW",
                                   permission_class="P2", autonomy_tier="T3")
        self.assertTrue(human_gate_required(request).required)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_unknown_operation_agrees_between_route_and_predicate(self):
        # R6 supersedes the R5 route for an unknown operation: it is now the canonical UNKNOWN_RUIN
        # SAFE_STOP, not the plain HUMAN_GATE route. Both entry points must still AGREE.
        self.assertTrue(human_gate_route("").required)
        predicate = human_gate_required(ApprovalRequest(operation=""))
        self.assertTrue(predicate.required)
        self.assertEqual(human_gate_route("").route, predicate.route)
        self.assertEqual(human_gate_route("").route, RUIN_SAFE_STOP_ROUTE)
        self.assertEqual(human_gate_route("").authority_edge, "RUIN:SAFE_STOP")

    def test_legacy_ruin_class_alias_is_accepted_only_when_canonical_absent(self):
        # NON-CANONICAL alias: without a canonical tier it still vetoes ...
        legacy_only = ApprovalRequest(operation="read", ruin_class="RUIN")
        self.assertEqual(human_gate_required(legacy_only).route, RUIN_HARD_VETO_ROUTE)
        # ... but a present canonical LOW/MEDIUM may NOT be weakened by the alias.
        canonical_wins = ApprovalRequest(operation="read", effect_risk_tier="LOW",
                                         permission_class="P2", ruin_class="RUIN")
        self.assertFalse(human_gate_required(canonical_wins).required)




# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R006 (R6): the OPERATION/ACTION_CLASS axis (DOC-03 L867/L874). An operation that cannot
# be classified is an UNKNOWN_RUIN-classed outcome and SAFE-STOPS; a KNOWN operation may only tighten
# or identify the route. The classification is effect-driven: it never reads how harmless a name looks.
# ---------------------------------------------------------------------------------------------
class TestCanonicalOperationAxisR6(unittest.TestCase):

    # The canonical 09.1 ACTION_EFFECT_CLASS_MATRIX names quoted by the R6 spec.
    CANONICAL_MATRIX = (
        "ACT-READ-LOCAL", "ACT-DESIGN-WRITE", "ACT-EXTERNAL-READ", "ACT-EXTERNAL-WRITE-REV",
        "ACT-EXTERNAL-WRITE-STATEFUL", "ACT-DATA-EXPORT", "ACT-SECRET-RESOLVE", "ACT-IDENTITY-RIGHTS",
        "ACT-MERGE", "ACT-DEPLOY-RELEASE", "ACT-FINANCIAL", "ACT-PHYSICAL", "ACT-DELETE-IRREV",
    )
    UNKNOWN_OPERATIONS = (
        "definitely-not-a-known-operation", "unknown_action", "delete", "merge",
        "create_or_update_file", "Read", "READ", "read ", " read", "ACT-READ",
    )
    CLASSIFICATIONS = (
        (None, None, None),
        ("LOW", "P2", "T2"),
        ("MEDIUM", "P1", "T1"),
        ("LOW", "P0", "T0"),
        ("HIGH", "P2", "T2"),
        ("CRITICAL", "P4", "T2"),
    )

    def _seam(self, request, approval="", **kwargs):
        route = human_gate_required(request)
        return assert_human_gate_satisfied(route, approval, request=request, **kwargs)

    def test_r6_01_unknown_operation_safe_stops_at_every_classification(self):
        for operation in self.UNKNOWN_OPERATIONS:
            for tier, permission, autonomy in self.CLASSIFICATIONS:
                with self.subTest(operation=operation, tier=tier, permission=permission):
                    request = _release_request(operation=operation, effect_risk_tier=tier,
                                               permission_class=permission, autonomy_tier=autonomy)
                    route = human_gate_required(request)
                    self.assertTrue(route.required)
                    self.assertNotEqual(route.route, NONE_ROUTE)
                    self.assertEqual(route.route, RUIN_SAFE_STOP_ROUTE)
                    self.assertEqual(route.authority_edge, "RUIN:SAFE_STOP")
                    with self.assertRaises(HumanGateBypassAttempt) as caught:
                        self._seam(request)
                    self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_r6_02_empty_and_non_string_operation_safe_stop(self):
        for operation in ("", " ", None, 17, ("read",), b"read"):
            with self.subTest(operation=repr(operation)):
                request = _release_request(operation=operation)
                route = human_gate_required(request)
                self.assertTrue(route.required)
                self.assertEqual(route.route, RUIN_SAFE_STOP_ROUTE)
                with self.assertRaises(HumanGateBypassAttempt) as caught:
                    self._seam(request)
                self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_r6_03_known_benign_operation_stays_ungated(self):
        for operation in ("read", "ACT-READ-LOCAL", "ACT-DESIGN-WRITE", "ACT-EXTERNAL-READ"):
            for tier in ("LOW", "MEDIUM"):
                for permission in ("P0", "P1", "P2"):
                    with self.subTest(operation=operation, tier=tier, permission=permission):
                        request = _release_request(operation=operation, effect_risk_tier=tier,
                                                   permission_class=permission)
                        route = human_gate_required(request)
                        self.assertFalse(route.required)
                        self.assertEqual(route.route, NONE_ROUTE)
                        # R7: the benign return requires the matching TRUSTED current request.
                        self.assertIsNone(self._seam(
                            request, ctx=_release_ctx(
                                request_resolver=_request_resolver(request))))

    def test_r6_04_known_high_risk_operation_gates_and_names_its_edge(self):
        for operation in sorted(HIGH_RISK_ACTIONS):
            with self.subTest(operation=operation):
                route = human_gate_required(_release_request(operation=operation))
                self.assertTrue(route.required)
                self.assertEqual(route.route, "ARTIFACT:HUMAN_GATE")
                self.assertEqual(route.authority_edge, "HUMAN_GATE:%s" % operation)
                with self.assertRaises(HumanGateBypassAttempt):
                    self._seam(_release_request(operation=operation))

    # The canonical read/design classes; their EFFECT is local and they carry no tightening of their
    # own, so at a benign asserted tier they remain ungated. Every OTHER canonical class tightens.
    NON_TIGHTENING_MATRIX = ("ACT-READ-LOCAL", "ACT-DESIGN-WRITE", "ACT-EXTERNAL-READ")

    def test_r6_05_canonical_matrix_is_known_and_effect_driven(self):
        for operation in self.CANONICAL_MATRIX:
            with self.subTest(operation=operation):
                # Every canonical name RESOLVES: the effect decides whether it tightens, so a
                # canonical name is never SAFE_STOPPED merely for being unrecognised.
                route = human_gate_required(_release_request(
                    operation=operation, effect_risk_tier="LOW", permission_class="P2"))
                self.assertNotEqual(route.route, RUIN_SAFE_STOP_ROUTE)
                if operation in self.NON_TIGHTENING_MATRIX:
                    self.assertFalse(route.required)
                    self.assertEqual(route.route, NONE_ROUTE)
                else:
                    self.assertTrue(route.required)
                    self.assertEqual(route.route, "ARTIFACT:HUMAN_GATE")
                    self.assertEqual(route.authority_edge, "HUMAN_GATE:%s" % operation)

    def test_r6_06_operation_may_tighten_but_never_weaken(self):
        # A KNOWN consequential class tightens a benign asserted tier ...
        tightened = human_gate_required(_release_request(
            operation="ACT-DELETE-IRREV", effect_risk_tier="LOW", permission_class="P2"))
        self.assertTrue(tightened.required)
        self.assertEqual(tightened.authority_edge, "HUMAN_GATE:ACT-DELETE-IRREV")
        # ... an unknown name can never weaken a P3 floor (it SAFE-STOPS) ...
        floor = human_gate_required(_release_request(
            operation="definitely-not-a-known-operation", effect_risk_tier="LOW",
            permission_class="P3"))
        self.assertTrue(floor.required)
        self.assertEqual(floor.route, RUIN_SAFE_STOP_ROUTE)
        # ... and no name weakens a canonical RUIN / UNKNOWN_RUIN effect veto.
        self.assertEqual(human_gate_required(_release_request(
            operation="read", effect_risk_tier="RUIN")).route, RUIN_HARD_VETO_ROUTE)
        self.assertEqual(human_gate_required(_release_request(
            operation="read", effect_risk_tier="UNKNOWN_RUIN")).route, RUIN_SAFE_STOP_ROUTE)

    def test_r6_07_unknown_operation_is_not_rescued_by_a_valid_token(self):
        request = _release_request(operation="definitely-not-a-known-operation")
        route = human_gate_required(request)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, _valid_token(), requesting_actor="human:dave",
                                        request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_r6_08_route_shim_and_predicate_agree_on_unknown_operations(self):
        for operation in self.UNKNOWN_OPERATIONS:
            with self.subTest(operation=operation):
                shim = human_gate_route(operation)
                predicate = human_gate_required(ApprovalRequest(operation=operation))
                self.assertEqual((shim.required, shim.route, shim.authority_edge),
                                 (predicate.required, predicate.route, predicate.authority_edge))
                self.assertEqual(shim.route, RUIN_SAFE_STOP_ROUTE)
        for operation in ("", None, 17):
            with self.subTest(operation=repr(operation)):
                shim = human_gate_route(operation)
                self.assertEqual(shim.route, RUIN_SAFE_STOP_ROUTE)
                self.assertTrue(shim.required)


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R008 (R4): the HumanGate seam is policy-bound to the REQUEST authn floor. The request
# carries `required_authn_assurance` (DOC-03 14.R / 15.2, AAC1|AAC2|AAC3) and a MISSING floor fails
# closed through the SAME gated seam - a bare default is never a proxy for a policy floor.
# ---------------------------------------------------------------------------------------------
class TestPolicyBoundAuthnFloorAtSeamR008(unittest.TestCase):

    def _seam(self, request):
        route = human_gate_required(request)
        ctx = _release_ctx(request_resolver=_request_resolver(request))
        return assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request,
            ctx=ctx)

    def test_r008_exact_floor_aac2_request_passes(self):
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3",
                                   required_authn_assurance="AAC2")
        self.assertIsNone(self._seam(request))

    def test_r008_missing_request_floor_fails_closed_at_the_seam(self):
        # R8: a gated request that DROPS its canonical floor is now a PI06 minimum-policy deny.
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3",
                                   required_authn_assurance="")
        original = _valid_token(approval_basis_hash=approval_basis_hash(
            R007_DECISION_BASIS, DIGEST, DIGEST, DIGEST, DIGEST, "1.0"))
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(human_gate_required(request), original,
                                        requesting_actor="human:dave", request=request,
                                        ctx=_release_ctx(request_resolver=_request_resolver(request)))
        self.assertEqual(str(caught.exception), "DENY_POLICY_FLOOR")

    def test_r008_canonical_floor_field_is_required_on_gated_requests(self):
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3",
                                   required_authn_assurance="AAC3")
        ctx = _release_ctx(request_resolver=_request_resolver(request))
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                human_gate_required(request), _valid_token(), requesting_actor="human:dave",
                request=request, ctx=ctx)
        self.assertEqual(str(caught.exception), "DENY_AUTHN")


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R007 (R7): the TRUSTED ROUTE-ADMISSION boundary (F-W2R6-EXT-001). A caller can no
# longer lower every route-driving field (operation / effect_risk_tier / permission_class /
# autonomy_tier) to a benign combination and skip the verifier through the `required=False` early
# return. When a request is supplied, its CURRENT canonical counterpart is resolved through the
# existing owner-injected `request_resolver` seam BEFORE the benign return, the caller request is
# pinned to it on the policy-owned fields, and the SUPPLIED route must equal the trusted-derived
# route on `required`, `route` and `authority_edge`.
# ---------------------------------------------------------------------------------------------
class TestR7TrustedRouteAdmission(unittest.TestCase):

    def _trusted_ctx(self, trusted):
        return _release_ctx(request_resolver=_request_resolver(trusted))

    def _deny(self, code, caller, trusted, route=None):
        route = route if route is not None else human_gate_required(caller)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=caller,
                                        ctx=self._trusted_ctx(trusted))
        self.assertEqual(str(caught.exception), code)

    # A1: a trusted read/CRITICAL/P4/T3/AAC3 request vs a caller read/LOW/P2/T2/AAC1 clone.
    def test_a1_trusted_critical_p4_t3_vs_caller_low_p2_t2_is_policy_mismatch(self):
        trusted = _release_request(
            operation="read", effect_risk_tier="CRITICAL", permission_class="P4",
            autonomy_tier="T3", required_authn_assurance="AAC3")
        caller = _release_request(
            operation="read", effect_risk_tier="LOW", permission_class="P2",
            autonomy_tier="T2", required_authn_assurance="AAC1")
        self.assertFalse(human_gate_required(caller).required)
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted)

    # A2: operation-only suppression - a trusted release vs a caller read.
    def test_a2_operation_only_suppression_is_policy_mismatch(self):
        trusted = _release_request(operation="release")
        caller = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        self.assertFalse(human_gate_required(caller).required)
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted)

    # A3: risk-only suppression - a trusted CRITICAL vs a caller LOW.
    def test_a3_risk_only_suppression_is_policy_mismatch(self):
        trusted = _release_request(operation="read", effect_risk_tier="CRITICAL")
        caller = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted)

    # A4: permission-only suppression - a trusted P4 vs a caller P2.
    def test_a4_permission_only_suppression_is_policy_mismatch(self):
        trusted = _release_request(operation="read", permission_class="P4")
        caller = _release_request(operation="read", permission_class="P2")
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted)

    # A5: autonomy-only suppression - a trusted T3 vs a caller T2.
    def test_a5_autonomy_only_suppression_is_policy_mismatch(self):
        trusted = _release_request(operation="read", autonomy_tier="T3")
        caller = _release_request(operation="read", effect_risk_tier="LOW", autonomy_tier="T2",
                                  permission_class="P2")
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted)

    # A6: combined suppression of every route-driving axis.
    def test_a6_combined_suppression_is_policy_mismatch(self):
        trusted = _release_request(
            operation="release", effect_risk_tier="CRITICAL", permission_class="P4",
            autonomy_tier="T3", required_authn_assurance="AAC3")
        caller = _release_request(
            operation="read", effect_risk_tier="LOW", permission_class="P2",
            autonomy_tier="T2", required_authn_assurance="AAC1")
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted)

    # A7: a fake benign NONE route plus a benign caller clone cannot hide a gated trusted request.
    def test_a7_fake_none_route_with_benign_clone_and_gated_trusted_is_denied(self):
        trusted = _release_request(operation="release")
        caller = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        fake_none = HumanGateRoute(False, NONE_ROUTE, "NONE")
        self._deny("DENY_REQUEST_POLICY_MISMATCH", caller, trusted, route=fake_none)

    # A8: an apparent benign caller with NO trusted resolver fails closed.
    def test_a8_benign_caller_without_a_resolver_fails_closed(self):
        caller = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        route = human_gate_required(caller)
        self.assertFalse(route.required)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=caller)
        self.assertEqual(str(caught.exception), "DENY_REQUEST_UNRESOLVED")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=caller,
                                        ctx=_release_ctx(request_resolver=None))
        self.assertEqual(str(caught.exception), "DENY_REQUEST_UNRESOLVED")

    # A9: a stale/foreign trusted request (resolver returns None for the caller request_id).
    def test_a9_stale_or_foreign_trusted_request_is_deny_request_unresolved(self):
        caller = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        foreign = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2",
                                   request_id="req-foreign")
        self._deny("DENY_REQUEST_UNRESOLVED", caller, foreign)

    # P1: an exact trusted == caller read/LOW/P2/T2 request is the permitted NONE positive control
    # and passes WITHOUT a token.
    def test_p1_exact_benign_request_passes_without_a_token(self):
        request = _release_request(
            operation="read", effect_risk_tier="LOW", permission_class="P2", autonomy_tier="T2")
        route = human_gate_required(request)
        self.assertFalse(route.required)
        self.assertEqual(route.route, NONE_ROUTE)
        self.assertIsNone(assert_human_gate_satisfied(
            route, "", request=request, ctx=self._trusted_ctx(request)))

    # P2: an exact trusted gated request with a valid current token/decision passes.
    def test_p2_exact_gated_request_with_valid_token_passes(self):
        request = _release_request()
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:alice", request=request,
            ctx=self._trusted_ctx(request)))

    # P3: a supplied route whose authority_edge disagrees with the trusted-derived route is an
    # understated route, even when required/route agree.
    def test_p3_supplied_route_authority_edge_mismatch_is_denied(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        trusted_route = human_gate_required(request)
        self.assertEqual(
            (trusted_route.required, trusted_route.route, trusted_route.authority_edge),
            (False, NONE_ROUTE, "NONE"))
        tampered = HumanGateRoute(False, NONE_ROUTE, "HUMAN_GATE:risk_tier")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(tampered, "", request=request,
                                        ctx=self._trusted_ctx(request))
        self.assertEqual(str(caught.exception), "ROUTE_UNDERSTATES_ACTION")



# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R008 (R8, F-W2R7-EXT-001): PI06 MINIMUM-POLICY CONFORMANCE. R6/R7 pin the caller to
# the TRUSTED request; this class proves the TRUSTED request must ITSELF meet the frozen PI06
# minimum floor, and that `required_coapprovals` must resolve to CURRENT canonical decisions.
# ---------------------------------------------------------------------------------------------
def _r8_release_decision(**overrides):
    fields = dict(
        decision_id="dec-1", request_id="req-1", decision="APPROVE", approver="human:carol",
        authority_class="HA1", authn_assurance_class="AAC3", reason_codes=("HG-RULE-001",),
        decided_at="2026-06-01T00:15:00Z", evidence_ref="evidence:decision-1",
        integrity_ref="integrity:decision-1",
    )
    fields.update(overrides)
    decision = HumanGateDecision(**fields)
    return replace(decision, decision_basis_hash=approval_decision_basis_hash(decision))


def _r8_release_request(**overrides):
    """The canonical-valid PI06 release request with a self-consistent decision basis."""
    return _canonical_release_request(
        decision_basis_hash=_r8_release_decision().decision_basis_hash, **overrides)


def _r8_release_token(request, **overrides):
    """A canonical-valid RELEASE token whose RECOMPUTABLE approval basis binds `request`."""
    fields = dict(
        operation=request.operation, authn_assurance_class="AAC3",
        independent_checker_required=True, independent_checker_evidence_ref="evidence:checker-1",
        rollback_ref=request.rollback_ref,
    )
    fields.update(overrides)
    fields["approval_basis_hash"] = approval_basis_hash(
        request.decision_basis_hash, request.effect_digest, request.generation_bundle_digest,
        request.rollback_digest, request.consumer_audience_hash, "1.0")
    return _valid_token(**fields)


def _r8_coapproval_decision(**overrides):
    fields = dict(
        decision_id="dec-ha5", request_id="req-1", decision="APPROVE", approver="human:dana",
        authority_class="HA5", authn_assurance_class="AAC3", reason_codes=("HG-RULE-COAPPROVE",),
        decided_at="2026-06-01T00:20:00Z", evidence_ref="evidence:decision-ha5",
        integrity_ref="integrity:decision-ha5",
    )
    fields.update(overrides)
    decision = HumanGateDecision(**fields)
    return replace(decision, decision_basis_hash=approval_decision_basis_hash(decision))


def _r8_coapproval_resolver(mapping=None):
    table = dict(mapping) if mapping is not None else {("req-1", "HA5"): _r8_coapproval_decision()}
    return lambda request_id, ref: table.get((request_id, ref))


def _r8_ctx(request, **overrides):
    fields = dict(
        commit_time="2026-06-01T00:30:00Z", expected_consumer_audience_hash=DIGEST,
        trusted_key_registry=_honest_registry, nonce_ledger=NonceLedger(), max_reauth_age_seconds=3600,
        decision_resolver=_decision_registry({"dec-1": _r8_release_decision()}),
        authority_policy=_authority_policy, request_resolver=_request_resolver(request),
        coapproval_resolver=_r8_coapproval_resolver(),
        independent_checker_evidence_ref="evidence:checker-1",
    )
    fields.update(overrides)
    return VerificationContext(**fields)


def _r8_verify(request, token=None, **ctx_overrides):
    token = _r8_release_token(request) if token is None else token
    return verify_approval_token(token, request, _r8_ctx(request, **ctx_overrides))


class TestR8PolicyConformance(unittest.TestCase):
    """A01-A14: a TRUSTED request weaker than the frozen PI06 minimum is refused; P01-P04 pass."""

    # A01: a release request claiming P2 is below the P5 minimum.
    def test_r8_a01_release_p2_is_denied(self):
        decision = _r8_verify(_r8_release_request(permission_class="P2"))
        self.assertEqual((decision.ok, decision.code), (False, "DENY_POLICY_FLOOR"))

    # A02: a release request claiming LOW risk is below CRITICAL.
    def test_r8_a02_release_low_risk_is_denied(self):
        decision = _r8_verify(_r8_release_request(effect_risk_tier="LOW"))
        self.assertEqual((decision.ok, decision.code), (False, "DENY_POLICY_FLOOR"))

    # A03: a release request at T2 is below the T3 law.
    def test_r8_a03_release_t2_is_denied(self):
        decision = _r8_verify(_r8_release_request(autonomy_tier="T2"))
        self.assertFalse(decision.ok)
        self.assertIn(decision.code, ("DENY_POLICY_FLOOR", "DENY_T3_CHECKER"))

    # A04: a release request at AAC2 is below the AAC3 floor.
    def test_r8_a04_release_aac2_is_denied(self):
        decision = _r8_verify(_r8_release_request(required_authn_assurance="AAC2"))
        self.assertFalse(decision.ok)
        self.assertIn(decision.code, ("DENY_POLICY_FLOOR", "DENY_AUTHN"))

    # A05: an explicitly T3 release with independent_checker_required=False is refused.
    def test_r8_a05_release_t3_without_checker_is_denied(self):
        decision = _r8_verify(_r8_release_request(independent_checker_required=False))
        self.assertEqual((decision.ok, decision.code), (False, "DENY_T3_CHECKER"))

    # A06: a required coapproval that does not resolve is DENY_COAPPROVAL - in the verifier AND gate.
    def test_r8_a06_missing_coapproval_is_denied(self):
        request = _r8_release_request()
        resolver = _r8_coapproval_resolver({})
        decision = _r8_verify(request, coapproval_resolver=resolver)
        self.assertEqual((decision.ok, decision.code), (False, "DENY_COAPPROVAL"))
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                human_gate_required(request), _r8_release_token(request),
                requesting_actor="human:alice", request=request,
                ctx=_r8_ctx(request, coapproval_resolver=resolver))
        self.assertEqual(str(caught.exception), "DENY_COAPPROVAL")

    # A07: a coapproval decision with a malformed (untrusted) decided_at is DENY_COAPPROVAL.
    def test_r8_a07_stale_coapproval_is_denied(self):
        resolver = _r8_coapproval_resolver(
            {("req-1", "HA5"): _r8_coapproval_decision(decided_at="not-a-time")})
        decision = _r8_verify(_r8_release_request(), coapproval_resolver=resolver)
        self.assertEqual((decision.ok, decision.code), (False, "DENY_COAPPROVAL"))

    # A08: a coapproval decision bound to ANOTHER request is DENY_COAPPROVAL.
    def test_r8_a08_foreign_request_coapproval_is_denied(self):
        resolver = _r8_coapproval_resolver(
            {("req-1", "HA5"): _r8_coapproval_decision(request_id="req-other")})
        decision = _r8_verify(_r8_release_request(), coapproval_resolver=resolver)
        self.assertEqual((decision.ok, decision.code), (False, "DENY_COAPPROVAL"))

    # A09: a revoked/superseded coapproval decision is DENY_COAPPROVAL.
    def test_r8_a09_revoked_or_superseded_coapproval_is_denied(self):
        for over in ({"revoked": True}, {"superseded": True}, {"decision": "DENY"}):
            with self.subTest(over=over):
                resolver = _r8_coapproval_resolver(
                    {("req-1", "HA5"): _r8_coapproval_decision(**over)})
                decision = _r8_verify(_r8_release_request(), coapproval_resolver=resolver)
                self.assertEqual((decision.ok, decision.code), (False, "DENY_COAPPROVAL"))

    # A10: a caller that DROPS a trusted required_coapproval is DENY_REQUEST_POLICY_MISMATCH.
    def test_r8_a10_caller_removes_trusted_coapproval_is_policy_mismatch(self):
        trusted = _r8_release_request()
        caller = _r8_release_request(required_coapprovals=())
        decision = _r8_verify(
            caller, token=_r8_release_token(caller),
            request_resolver=_request_resolver(trusted))
        self.assertEqual((decision.ok, decision.code), (False, "DENY_REQUEST_POLICY_MISMATCH"))

    # A11: a P4 secret resolve lacking the {HA1,HA3} clause is a PI06 authority-floor deny.
    def test_r8_a11_secret_missing_clause_is_denied(self):
        request = _release_request(
            operation="ACT-SECRET-RESOLVE", effect_risk_tier="CRITICAL", permission_class="P4",
            required_authority="HA1", required_coapprovals=(), required_authn_assurance="AAC3")
        decision = _r8_verify(request, token=_valid_token(operation="ACT-SECRET-RESOLVE"))
        self.assertFalse(decision.ok)
        self.assertIn(decision.code, ("DENY_POLICY_FLOOR", "DENY_AUTHORITY"))

    # A12: a P3 reversible external write presented as P2 is below the permission floor.
    def test_r8_a12_external_write_as_p2_is_denied(self):
        request = _release_request(
            operation="ACT-EXTERNAL-WRITE-REV", effect_risk_tier="MEDIUM",
            permission_class="P2", required_authority="HA1")
        decision = _r8_verify(request, token=_valid_token())
        self.assertEqual((decision.ok, decision.code), (False, "DENY_POLICY_FLOOR"))

    # A13: a duplicate / malformed coapproval ref is a deterministic DENY_COAPPROVAL.
    def test_r8_a13_malformed_coapproval_ref_is_denied(self):
        for refs in (("HA5", "HA5"), ("HA5", "  "), ("HA5", 17), ["HA5"]):
            with self.subTest(refs=refs):
                decision = _r8_verify(_r8_release_request(required_coapprovals=refs))
                self.assertEqual((decision.ok, decision.code), (False, "DENY_COAPPROVAL"))

    # A14: a required coapproval with NO owner resolver is TEMP_CLOSED (never "skip").
    def test_r8_a14_coapproval_without_resolver_is_temp_closed(self):
        decision = _r8_verify(_r8_release_request(), coapproval_resolver=None)
        self.assertEqual((decision.ok, decision.code), (False, "TEMP_CLOSED_AUTHORITY_RESOLUTION"))

    # P01: a valid benign read keeps the low-friction NONE return (no floor, no token).
    def test_r8_p01_benign_read_unchanged(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        route = human_gate_required(request)
        self.assertFalse(route.required)
        self.assertIsNone(assert_human_gate_satisfied(
            route, "", request=request, ctx=_release_ctx(request_resolver=_request_resolver(request))))

    # P02: a valid P3 reversible external write passes the floor.
    def test_r8_p02_valid_external_write_passes(self):
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3",
                                   required_authority="HA1")
        ctx = _release_ctx(request_resolver=_request_resolver(request))
        decision = verify_approval_token(_valid_token(), request, ctx)
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_required(request), _valid_token(), requesting_actor="human:alice",
            request=request, ctx=_release_ctx(request_resolver=_request_resolver(request))))

    # P03: a FULL canonical P5 release baseline (P5/CRITICAL/T3/HA1+HA5/AAC3/checker) passes.
    def test_r8_p03_full_release_baseline_passes(self):
        request = _r8_release_request()
        decision = _r8_verify(request)
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_required(request), _r8_release_token(request),
            requesting_actor="human:alice", request=request, ctx=_r8_ctx(request)))

    # P04: a DOMAIN-TIGHTER release (an extra required coapproval) is preserved, not rejected.
    def test_r8_p04_domain_tighter_policy_is_preserved(self):
        request = _r8_release_request(required_coapprovals=("HA3", "HA5"))
        resolver = _r8_coapproval_resolver({
            ("req-1", "HA3"): _r8_coapproval_decision(decision_id="dec-ha3", authority_class="HA3"),
            ("req-1", "HA5"): _r8_coapproval_decision(),
        })
        decision = _r8_verify(request, coapproval_resolver=resolver)
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))


if __name__ == "__main__":
    unittest.main()
