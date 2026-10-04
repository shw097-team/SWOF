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
    approval_basis_hash, canonical_payload_bytes,
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
    "519bb5449ba2548c613d41292cdcee499608ea651fa2b06f5198f98752c6d937"
)

# WO-SWOF-W2-R007: the LITERAL frozen ApprovalDecisionBasisV1 JCS digest (same fixture as the
# currentness suite); it is an independent source constant, not a call to the helper under test.
R007_DECISION_BASIS = "85d40a3e42a96bebd63c1cf323d7d359825c43ed6447a57c38ba5897525ab4f7"


def _authority_policy(decision_authority_class, required_authority):
    """TEST owner policy: only the exact HA class the request declares is sufficient."""
    return decision_authority_class == required_authority


def _current_decision(**overrides):
    fields = dict(
        decision_id="dec-1", request_id="req-1", decision="APPROVE", approver="human:carol",
        authority_class="HA3", authn_assurance_class="AAC2", reason_codes=("HG-RULE-001",),
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
        subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice", operation="release",
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
    fields = dict(
        subject="svc-a", subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice",
        operation="release", target_system="swof", resource=("artifact:app",), environment="prod",
        purpose_ref="purpose:release", scope=("release",), data_class="INTERNAL",
        effect_digest=DIGEST, consumer_audience_hash=DIGEST, effect_risk_tier="LOW",
        permission_class="P2", autonomy_tier="T2", required_authority="HA3",
        required_authn_assurance="AAC2", adapter_kind="canonical",
        rollback_ref="rollback:1", independent_checker_required=False, ruin_class="NONE",
        request_id="req-1", decision_id="dec-1", decision_basis_hash=R007_DECISION_BASIS,
        generation_bundle_digest=DIGEST, rollback_digest=DIGEST,
    )
    fields.update(overrides)
    return ApprovalRequest(**fields)


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
        request = _release_request(effect_risk_tier="LOW", permission_class="P3")
        route = human_gate_required(request)
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:alice", request=request,
            ctx=_release_ctx()))


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R007: the gated seam must carry the decision/authority lineage and FAIL CLOSED when
# no canonical current decision is resolvable - a signature is never a proxy for authority.
# ---------------------------------------------------------------------------------------------
class TestGatedAuthorityLineageR007(unittest.TestCase):

    def _seam(self, ctx):
        request = _release_request(effect_risk_tier="LOW", permission_class="P3")
        route = human_gate_required(request)
        return assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request, ctx=ctx)

    def test_gated_route_without_a_resolvable_decision_fails_closed(self):
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(_release_ctx(decision_resolver=None))
        self.assertEqual(str(caught.exception), "DENY_DECISION_UNRESOLVED")

    def test_gated_route_with_insufficient_authority_fails_closed(self):
        resolver = _decision_registry({"dec-1": _current_decision(authority_class="HA1")})
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
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                human_gate_route("release"), forged, requesting_actor="human:alice",
                request=_release_request(), ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_TOKEN_INTEGRITY")

    def test_real_signature_passes(self):
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_route("release"), _valid_token(), requesting_actor="human:alice",
            request=_release_request(), ctx=_release_ctx()))


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
                self.assertIsNone(self._seam(request))

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
                        self.assertIsNone(self._seam(request))

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
                route = human_gate_required(_release_request(operation=operation))
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
        return assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request,
            ctx=_release_ctx())

    def test_r008_exact_floor_aac2_request_passes(self):
        request = _release_request(effect_risk_tier="LOW", permission_class="P3",
                                   required_authn_assurance="AAC2")
        self.assertIsNone(self._seam(request))

    def test_r008_missing_request_floor_fails_closed_at_the_seam(self):
        # Every other axis is satisfiable (LOW/P2, HA3 decision, AAC2 token); only the floor is absent.
        request = _release_request(effect_risk_tier="LOW", permission_class="P2",
                                   required_authn_assurance="")
        original = _valid_token(approval_basis_hash=approval_basis_hash(
            R007_DECISION_BASIS, DIGEST, DIGEST, DIGEST, DIGEST, "1.0"))
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(human_gate_required(request), original,
                                        requesting_actor="human:dave", request=request,
                                        ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_AUTHN")

    def test_r008_canonical_floor_field_is_required_on_gated_requests(self):
        request = _release_request(effect_risk_tier="LOW", permission_class="P3",
                                   required_authn_assurance="AAC3")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "DENY_AUTHN")


if __name__ == "__main__":
    unittest.main()
