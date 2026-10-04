"""WO-SWOF-W2 acceptance tests: rights currentness, the canonical gate predicate and the exact-
bound, RFC8785-framed, Ed25519-verified human approval token.

Every failing case must FAIL CLOSED with an exact code; the positive controls must PASS. Nothing
here reads a wall clock: currentness is always an explicit trusted `now`/`commit_time`. The
signing key is a TEST Ed25519 key; the library itself performs no key management, it only defines
the canonical bytes and delegates the public-key lookup to the injected resolver.
"""
import base64
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from security.humangate import (  # noqa: E402
    APPROVAL_BASIS_FRAME, DOMAIN_FRAME, JCS_PROFILE, ApprovalDecision, ApprovalRequest,
    ApprovalToken, JCSError, NonceLedger, VerificationContext, approval_basis_hash,
    canonical_payload_bytes, jcs_dumps, verify_approval_token,
)
from security.rights import (  # noqa: E402
    EFFECT_RISK_TIERS, HumanGateBypassAttempt, HumanGateRoute, RightsDenied, RightsScope,
    assert_credential_scope, assert_human_gate_satisfied, check_rights, currentness_required,
    human_gate_required, human_gate_route,
)

NOW = "2026-06-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"
COMMIT = "2026-06-01T00:30:00Z"

DIGEST = "a" * 64
SIGNATURE = "A" * 86

# WO-SWOF-W2-R004: the signature is a REAL Ed25519 signature. The TEST key never leaves this
# module; the library performs the verification against a public key resolved by the registered
# resolver, and only the resolver supplies key material.
_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_PUBLIC_BYTES = _PRIVATE_KEY.public_key().public_bytes_raw()

BASIS = approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0")


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
        authn_session_generation=7, credential_generation=8, approval_basis_hash=BASIS,
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
        permission_class="P2", autonomy_tier="T2", required_authority="HUMAN_GATE:release",
        rollback_ref="rollback:1", independent_checker_required=False, ruin_class="NONE",
        request_id="req-1", decision_id="dec-1", decision_basis_hash=DIGEST,
        generation_bundle_digest=DIGEST, rollback_digest=DIGEST,
    )
    fields.update(overrides)
    return ApprovalRequest(**fields)


def _release_ctx(**overrides):
    fields = dict(
        commit_time=COMMIT,
        expected_consumer_audience_hash=DIGEST,
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
        decision = _verify(request_over={"effect_risk_tier": "LOW", "permission_class": "P3",
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


class TestSignatureDelegationR2(unittest.TestCase):
    """BLK-1: the injected resolver yields a key and a REAL Ed25519 check runs over framed bytes."""

    def test_r2_01_forged_signature_shape_is_refused_by_real_ed25519(self):
        # An 86-char shape-valid signature that does NOT correspond to the framed token payload is
        # refused, because the verifier now performs a REAL Ed25519 verification, not a shape check.
        forged = _valid_token(signature=SIGNATURE)
        self.assertEqual(len(forged.signature), 86)
        decision = verify_approval_token(forged, _release_request(), _release_ctx())
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

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

    def test_r2_05_non_resolving_or_raising_resolver_is_denied(self):
        def _raiser(*args):
            raise RuntimeError("resolver unavailable")

        cases = {
            "none": lambda *args: None,
            "false": lambda *args: False,
            "raises": _raiser,
            "wrong_arity": lambda issuer_id: b"",
            "non_key_object": lambda *args: object(),
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
        self.assertTrue(first.startswith(DOMAIN_FRAME))
        self.assertNotEqual(first, canonical_payload_bytes(_valid_token(nonce="nonce-2")))
        body = json.loads(first[len(DOMAIN_FRAME):].decode("utf-8"))
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
        request = _release_request(effect_risk_tier="LOW", permission_class="P3")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "HG-2026-0007", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r2_12_p3_request_with_a_valid_typed_token_passes(self):
        route = human_gate_route("release")
        request = _release_request(effect_risk_tier="LOW", permission_class="P3")
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request,
            ctx=_release_ctx()))


# WO-SWOF-W2-R003: the canonical ApprovalToken 1.0.0 required-name set (PI-PKG-06::DOC-03
# section 15). Embedded here as a literal so a future drift in the schema fails loudly. The
# conditional `independent_checker_evidence_ref` is deliberately ABSENT: it is required only when
# `independent_checker_required` is true (the schema encodes that in allOf/if-then, and the
# verifier enforces it in the checker stage).
CANONICAL_REQUIRED_NAMES = frozenset({
    "token_id", "request_id", "decision_id", "subject", "subject_hash", "semantic_version",
    "actor", "operation", "target_system", "resource", "environment", "purpose_ref", "scope",
    "data_class", "effect_digest", "consumer_audience_hash", "approver", "authority_class",
    "approver_authn_context_ref", "authn_assurance_class", "reauthenticated_at",
    "authn_session_generation", "credential_generation", "approval_basis_hash",
    "if06b_version", "payload_schema_version", "min_reader_version", "writer_version",
    "compatibility_class", "evidence_link", "independent_checker_required", "issued_at",
    "expires_at", "nonce", "rollback_ref", "token_state", "consumer", "integrity_profile_id",
    "issuer_id", "key_id", "key_generation", "signature",
})


class TestCanonicalEnvelopeR3(unittest.TestCase):
    """WO-SWOF-W2-R003: the runtime type is STRICTER OR EQUAL to the canonical registry."""

    def _schema(self):
        path = Path(__file__).resolve().parents[3] / "schemas" / "security" / "approval_token.schema.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_r3_01_unsupported_abi_major_is_refused(self):
        decision = _verify(token_over={"if06b_version": "2.0"})
        self.assertEqual((decision.ok, decision.code), (False, "IF06B_VERSION_UNSUPPORTED"))

    def test_r3_02_missing_or_non_string_if06b_version_is_refused(self):
        for value in ("", None, 1):
            with self.subTest(value=value):
                decision = _verify(token_over={"if06b_version": value})
                self.assertEqual((decision.ok, decision.code), (False, "IF06B_VERSION_UNSUPPORTED"))

    def test_r3_03_wrong_payload_schema_version_is_refused(self):
        decision = _verify(token_over={"payload_schema_version": "2.0.0"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_SCHEMA"))

    def test_r3_04_unknown_writer_version_is_refused(self):
        decision = _verify(token_over={"writer_version": "SOMETHING-ELSE"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_SCHEMA"))

    def test_r3_05_unknown_compatibility_class_is_refused(self):
        decision = _verify(token_over={"compatibility_class": "LAX_MINOR"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_SCHEMA"))

    def test_r3_06_empty_evidence_link_is_refused(self):
        for value in ("", "   ", None):
            with self.subTest(value=value):
                decision = _verify(token_over={"evidence_link": value})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_SCHEMA"))

    def test_r3_07_min_reader_newer_than_reader_is_refused(self):
        for value in ("2.0", "1.1", "9.9"):
            with self.subTest(value=value):
                decision = _verify(token_over={"min_reader_version": value})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_SCHEMA"))

    def test_r3_08_valid_token_with_all_envelope_fields_is_approved(self):
        decision = _verify(token_over={
            "if06b_version": "1.0", "payload_schema_version": "1.0.0", "min_reader_version": "1.0",
            "writer_version": "DOC03-r2", "compatibility_class": "STRICT_MAJOR_ADDITIVE_MINOR",
            "evidence_link": "evidence:approval-basis-1",
        })
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r3_09_schema_required_equals_canonical_42(self):
        required = self._schema()["required"]
        self.assertEqual(len(required), 42)
        self.assertEqual(set(required), set(CANONICAL_REQUIRED_NAMES))
        self.assertNotIn("independent_checker_evidence_ref", required)

    def test_r3_10_version_syntax_is_exact(self):
        # R4 3.6: "1" and "1.0.0.0" are malformed, not merely unequal.
        data = self._schema()["properties"]
        self.assertEqual(data["if06b_version"]["pattern"], "^[0-9]+\\.[0-9]+$")
        self.assertEqual(data["min_reader_version"]["pattern"], "^[0-9]+\\.[0-9]+$")
        self.assertNotIn("pattern", data["payload_schema_version"])
        self.assertEqual(data["payload_schema_version"]["const"], "1.0.0")


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R004 (R4). D1 - ONE canonical gate predicate; the operation name may tighten but
# never weaken a risk/permission requirement.
# ---------------------------------------------------------------------------------------------
class TestCanonicalGatePredicateD1(unittest.TestCase):

    def _seam(self, request, approval="", **kwargs):
        route = human_gate_required(request)
        return assert_human_gate_satisfied(route, approval, request=request, **kwargs)

    def test_r4_d1_01_p3_benign_operation_without_token_is_denied(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P3")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r4_d1_02_p4_benign_operation_without_token_is_denied(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P4")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r4_d1_03_p5_benign_operation_without_token_is_denied(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P5")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r4_d1_04_p3_permission_class_only_benign_operation_is_denied(self):
        # effect_risk_tier stays P2; the permission class alone must gate the benign operation.
        request = _release_request(operation="read", permission_class="P3")
        self.assertTrue(human_gate_required(request).required)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request)
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r4_d1_05_p3_benign_operation_with_valid_token_passes(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P3")
        self.assertIsNone(self._seam(
            request, _valid_token(operation="read"), requesting_actor="human:dave",
            ctx=_release_ctx()))

    def test_r4_d1_06_p2_benign_operation_without_token_is_allowed(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        self.assertEqual(human_gate_required(request).route, "NONE")
        self.assertFalse(human_gate_required(request).required)
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_route("read"), "", request=request))

    def test_r4_d1_07_explicit_high_risk_operation_with_p2_is_gated(self):
        request = _release_request(operation="release", effect_risk_tier="LOW", permission_class="P2")
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertEqual(route.authority_edge, "HUMAN_GATE:release")
        with self.assertRaises(HumanGateBypassAttempt):
            assert_human_gate_satisfied(route, "", request=request, ctx=_release_ctx())


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R004 (R4). D2 - ruin precedence BEFORE any approval; a token can never authorize it.
# ---------------------------------------------------------------------------------------------
class TestRuinPrecedenceD2(unittest.TestCase):

    def test_r4_d2_01_valid_token_with_ruin_is_hard_veto(self):
        decision = _verify(request_over={"effect_risk_tier": "RUIN"})
        self.assertEqual((decision.ok, decision.code), (False, "HARD_VETO_RUIN"))

    def test_r4_d2_02_valid_token_with_unknown_ruin_is_safe_stop(self):
        decision = _verify(request_over={"effect_risk_tier": "UNKNOWN_RUIN"})
        self.assertEqual((decision.ok, decision.code), (False, "SAFE_STOP_UNKNOWN_RUIN"))

    def test_r4_d2_03_no_token_with_ruin_is_hard_veto_at_the_seam(self):
        request = _release_request(effect_risk_tier="RUIN")
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertEqual(route.route, "ARTIFACT:RUIN_HARD_VETO")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_r4_d2_04_valid_token_with_ruin_is_hard_veto_at_the_seam(self):
        request = _release_request(effect_risk_tier="RUIN")
        route = human_gate_required(request)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                route, _valid_token(), requesting_actor="human:dave", request=request,
                ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_r4_d2_05_valid_token_with_unknown_ruin_is_safe_stop_at_the_seam(self):
        request = _release_request(effect_risk_tier="UNKNOWN_RUIN")
        route = human_gate_required(request)
        self.assertEqual(route.route, "ARTIFACT:RUIN_SAFE_STOP")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                route, _valid_token(), requesting_actor="human:dave", request=request,
                ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_r4_d2_06_ruin_predicate_is_first(self):
        # ruin precedence must not depend on the risk tier: a P2 RUIN request is still vetoed.
        param = _release_request(effect_risk_tier="RUIN", permission_class="P2")
        self.assertEqual(human_gate_required(param).authority_edge, "RUIN:HARD_VETO")


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R004 (R4). D3 - canonical integrity, basis and lineage.
# ---------------------------------------------------------------------------------------------
class TestTokenIntegrityLineageBasisD3(unittest.TestCase):

    def test_r4_d3_01_signature_over_non_framed_payload_is_denied(self):
        token = _valid_token(signature="A" * 86)
        body = {name: getattr(token, name)
                for name in token.__dataclass_fields__ if name != "signature"}
        forged = replace(token, signature=_sign_payload(jcs_dumps(body)))
        decision = verify_approval_token(forged, _release_request(), _release_ctx())
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r4_d3_02_signature_over_framed_but_non_jcs_payload_is_denied(self):
        token = _valid_token(signature="A" * 86)
        body = {name: getattr(token, name)
                for name in token.__dataclass_fields__ if name != "signature"}
        non_jcs = json.dumps(body, sort_keys=True).encode("utf-8")  # spaces => not JCS
        forged = replace(token, signature=_sign_payload(DOMAIN_FRAME + non_jcs))
        decision = verify_approval_token(forged, _release_request(), _release_ctx())
        self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r4_d3_03_unknown_key_or_wrong_generation_is_denied(self):
        for over in ({"key_generation": 99}, {"key_id": "key-x"}, {"issuer_id": "issuer-x"}):
            with self.subTest(over=over):
                decision = _verify(token_over=over)
                self.assertEqual((decision.ok, decision.code), (False, "DENY_TOKEN_INTEGRITY"))

    def test_r4_d3_04_real_ed25519_positive_control_passes(self):
        # A registry returning the correct raw public-key bytes over a correctly signed token PASSES.
        decision = _verify(ctx_over={"trusted_key_registry": _honest_registry})
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r4_d3_05_wrong_request_or_decision_id_is_denied(self):
        for over in ({"request_id": "req-x"}, {"decision_id": "dec-x"}):
            with self.subTest(over=over):
                decision = _verify(token_over=over)
                self.assertEqual((decision.ok, decision.code), (False, "DENY_EXACT_BINDING"))

    def test_r4_d3_06_wrong_approval_basis_hash_is_denied(self):
        decision = _verify(token_over={"approval_basis_hash": "b" * 64})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_APPROVAL_BASIS"))

    def test_r4_d3_07_request_declares_a_generation_ctx_lacks(self):
        decision = _verify(request_over={"rights_generation": 5})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))

    def test_r4_d3_08_declared_generation_must_match_ctx(self):
        decision = _verify(request_over={"rights_generation": 5}, ctx_over={"rights_generation": 6})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))
        matched = _verify(request_over={"credential_generation": 8},
                          ctx_over={"credential_generation": 8})
        self.assertEqual((matched.ok, matched.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r4_d3_09_gated_request_with_absent_or_malformed_audience_is_denied(self):
        for value in (None, "", "not-a-digest", "b" * 63):
            with self.subTest(value=value):
                decision = _verify(ctx_over={"expected_consumer_audience_hash": value})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_AUDIENCE_MISMATCH"))

    def test_r4_d3_10_checker_required_true_missing_ref_is_denied(self):
        decision = _verify(token_over={
            "independent_checker_required": True,
            "independent_checker_evidence_ref": "evidence:one",
        })
        self.assertEqual((decision.ok, decision.code), (False, "DENY_T3_CHECKER"))

    def test_r4_d3_11_t3_forces_checker_required_true(self):
        decision = _verify(request_over={"autonomy_tier": "T3"})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_T3_CHECKER"))

    def test_r4_d3_12_checker_required_true_matching_ref_passes(self):
        decision = _verify(
            token_over={"independent_checker_required": True,
                        "independent_checker_evidence_ref": "evidence:one"},
            ctx_over={"independent_checker_evidence_ref": "evidence:one"},
        )
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r4_d3_13_basis_recipe_is_exact(self):
        import hashlib
        expected = hashlib.sha256(
            APPROVAL_BASIS_FRAME + ("\n".join((DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0")))
            .encode("utf-8")).hexdigest()
        self.assertEqual(approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0"),
                         expected)
        self.assertEqual(approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0"), BASIS)


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R004 (R4) section 3.1 - RFC 8785 JCS properties.
# ---------------------------------------------------------------------------------------------
class TestJCSRFC8785(unittest.TestCase):

    def test_jcs_01_key_ordering_is_by_utf16_code_units(self):
        self.assertEqual(
            jcs_dumps({"b": 1, "a": 2, "ab": 3, "A": 4}),
            b'{"A":4,"a":2,"ab":3,"b":1}')
        # U+FFFD sorts after U+E000 in UTF-16 code units; a naive codepoint sort would differ.
        self.assertEqual(jcs_dumps({"\ue000": 1, "\ufffd": 2}),
                         '{"\ue000":1,"\ufffd":2}'.encode("utf-8"))

    def test_jcs_02_output_has_no_insignificant_whitespace(self):
        self.assertEqual(jcs_dumps({"a": 1, "b": [1, 2, 3]}), b'{"a":1,"b":[1,2,3]}')
        self.assertNotIn(b" ", jcs_dumps({"a": [1, 2], "b": {"c": 3}}))

    def test_jcs_03_integers_render_without_a_fraction(self):
        self.assertEqual(jcs_dumps(1), b"1")
        self.assertEqual(jcs_dumps(1.0), b"1")
        self.assertEqual(jcs_dumps(-7), b"-7")
        self.assertEqual(jcs_dumps({"n": 1000000}), b'{"n":1000000}')

    def test_jcs_04_non_ascii_string_round_trips(self):
        original = {"note": "caf\u00e9 \u2013 \u4e2d\u6587 \U0001f600"}
        encoded = jcs_dumps(original)
        self.assertEqual(json.loads(encoded.decode("utf-8")), original)

    def test_jcs_05_literals_and_arrays_in_order(self):
        self.assertEqual(jcs_dumps([True, False, None, []]), b"[true,false,null,[]]")

    def test_jcs_06_profile_is_not_json_dumps(self):
        self.assertEqual(JCS_PROFILE, "RFC8785")
        # json.dumps would emit "1.0"; JCS emits the shortest ECMAScript integer form "1".
        self.assertNotEqual(jcs_dumps(1.0), json.dumps(1.0).encode("utf-8"))

    def test_jcs_07_unsupported_numbers_raise_rather_than_guess(self):
        for value in (float("nan"), float("inf"), 2 ** 53 + 1):
            with self.subTest(value=repr(value)):
                with self.assertRaises(JCSError):
                    jcs_dumps(value)




class TestFailClosedTypeHardeningR4(unittest.TestCase):
    """R4: a non-canonical request/ctx and a non-canonical ruin class fail closed, never raise."""

    def test_non_canonical_request_fails_closed(self):
        decision = verify_approval_token(_valid_token(), object(), _release_ctx())
        self.assertEqual((decision.ok, decision.code),
                         (False, "NOT_A_CANONICAL_APPROVAL_TOKEN"))

    def test_non_canonical_ctx_fails_closed(self):
        decision = verify_approval_token(_valid_token(), _release_request(), object())
        self.assertEqual((decision.ok, decision.code),
                         (False, "NOT_A_CANONICAL_APPROVAL_TOKEN"))

    def test_non_canonical_ruin_class_is_safe_stop(self):
        for value in ("ruin", "RUIN_CLASS", 1, None):
            with self.subTest(value=value):
                decision = _verify(request_over={"ruin_class": value})
                self.assertEqual((decision.ok, decision.code),
                                 (False, "SAFE_STOP_UNKNOWN_RUIN"))

    def test_every_declared_generation_is_checked_not_only_the_first(self):
        # credential_generation is declared and matches ctx, but rights_generation is declared and
        # absent from ctx: the second declaration must still be refused.
        decision = _verify(
            request_over={"credential_generation": 8, "rights_generation": 5},
            ctx_over={"credential_generation": 8},
        )
        self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))

    def test_a_generation_without_a_token_analog_is_never_satisfied(self):
        # rights_generation has no canonical token field, so a context that supplies it makes the
        # token stale even when the request agrees: fail closed, never a silent skip.
        decision = _verify(
            request_over={"rights_generation": 5}, ctx_over={"rights_generation": 5})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_STALE_GENERATION"))

    def test_all_declared_token_generations_matching_passes(self):
        decision = _verify(
            request_over={"credential_generation": 8, "authn_session_generation": 7},
            ctx_over={"credential_generation": 8, "authn_session_generation": 7},
        )
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))


class TestJCSNumberForms(unittest.TestCase):
    """R4 3.1: ECMAScript Number::toString forms, and RAISE rather than emit a wrong shape."""

    def test_fraction_free_floats_render_as_integers(self):
        self.assertEqual(jcs_dumps(1.0), b"1")
        self.assertEqual(jcs_dumps(-0.0), b"0")
        self.assertEqual(jcs_dumps(1e20), b"100000000000000000000")

    def test_small_decimal_float_expands_without_an_exponent(self):
        self.assertEqual(jcs_dumps(0.000015), b"0.000015")

    def test_fractional_float_keeps_its_shortest_form(self):
        self.assertEqual(jcs_dumps(1000000.5), b"1000000.5")
        self.assertEqual(jcs_dumps(-1.5), b"-1.5")

    def test_negative_and_large_integers(self):
        self.assertEqual(jcs_dumps(-7), b"-7")
        self.assertEqual(jcs_dumps(2 ** 53 - 1), b"9007199254740991")

    def test_out_of_range_values_raise(self):
        for value in (2 ** 53, 1e-7, 1e21):
            with self.subTest(value=repr(value)):
                with self.assertRaises(JCSError):
                    jcs_dumps(value)


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R005 (R5). Canonical EffectRiskTier domain, ruin precedence from the canonical field,
# fail-closed enums, and the typed-decision nonce-ledger hardening.
# ---------------------------------------------------------------------------------------------
class TestCanonicalRuinAndFailClosedEnumsR5(unittest.TestCase):

    def test_r5_00_canonical_risk_domain_is_exact(self):
        self.assertEqual(EFFECT_RISK_TIERS,
                         ("LOW", "MEDIUM", "HIGH", "CRITICAL", "RUIN", "UNKNOWN_RUIN"))

    def test_r5_01_canonical_ruin_with_valid_token_is_hard_veto(self):
        decision = _verify(request_over={"effect_risk_tier": "RUIN"})
        self.assertEqual((decision.ok, decision.code), (False, "HARD_VETO_RUIN"))

    def test_r5_02_canonical_unknown_ruin_with_valid_token_is_safe_stop(self):
        decision = _verify(request_over={"effect_risk_tier": "UNKNOWN_RUIN"})
        self.assertEqual((decision.ok, decision.code), (False, "SAFE_STOP_UNKNOWN_RUIN"))

    def test_r5_03_canonical_ruin_without_token_is_hard_veto_at_the_seam(self):
        request = _release_request(effect_risk_tier="RUIN")
        route = human_gate_required(request)
        self.assertEqual((route.required, route.route), (True, "ARTIFACT:RUIN_HARD_VETO"))
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "HARD_VETO_RUIN")

    def test_r5_04_malformed_effect_risk_tier_is_safe_stop_not_ungated(self):
        for bad in ("p3", "ruin", ""):
            with self.subTest(value=bad):
                decision = _verify(request_over={"effect_risk_tier": bad})
                self.assertEqual((decision.ok, decision.code), (False, "SAFE_STOP_UNKNOWN_RUIN"))

    def test_r5_05_critical_and_high_gate_a_benign_operation_at_the_seam(self):
        for tier in ("CRITICAL", "HIGH"):
            with self.subTest(tier=tier):
                request = _release_request(operation="read", effect_risk_tier=tier,
                                           permission_class="P2")
                with self.assertRaises(HumanGateBypassAttempt) as caught:
                    assert_human_gate_satisfied(
                        human_gate_required(request), "", request=request, ctx=_release_ctx())
                self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r5_06_malformed_permission_class_is_refused_not_ungated(self):
        for bad in ("p3", "P3 ", " P3", "", "P9"):
            with self.subTest(value=bad):
                request = _release_request(operation="read", effect_risk_tier="LOW",
                                           permission_class=bad)
                self.assertTrue(human_gate_required(request).required)

    def test_r5_07_t3_benign_operation_requires_a_token(self):
        request = _release_request(operation="read", effect_risk_tier="LOW",
                                   permission_class="P2", autonomy_tier="T3")
        self.assertTrue(human_gate_required(request).required)
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(
                human_gate_required(request), "", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r5_08_malformed_nonce_ledger_returns_a_typed_decision(self):
        class _NoReserve:
            pass

        for ledger in (_NoReserve(), object(), 17, "not-a-ledger"):
            with self.subTest(ledger=repr(ledger)):
                decision = _verify(ctx_over={"nonce_ledger": ledger})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_REPLAY"))

    def test_r5_09_route_and_predicate_agree_on_the_unknown_operation(self):
        # D6: both entry points must agree. human_gate_route("") is exactly
        # human_gate_required(ApprovalRequest(operation="")): an unknown operation is gated by the
        # ONE canonical predicate, not by a second code path.
        self.assertTrue(human_gate_route("").required)
        predicate = human_gate_required(ApprovalRequest(operation=""))
        self.assertTrue(predicate.required)
        self.assertEqual(human_gate_route("").route, predicate.route)

    def test_r5_10_legacy_ruin_alias_cannot_weaken_a_canonical_value(self):
        # A canonical LOW/MEDIUM with a legacy ruin alias present stays benign: the alias is
        # NON-CANONICAL and may never weaken a present canonical value.
        request = _release_request(operation="read", effect_risk_tier="LOW",
                                   permission_class="P2", ruin_class="RUIN")
        self.assertFalse(human_gate_required(request).required)
        self.assertEqual(_verify(request_over={"effect_risk_tier": "LOW",
                                               "permission_class": "P2",
                                               "ruin_class": "RUIN"}).code,
                         "APPROVE_BASIS_SATISFIED")

    def test_r5_11_legacy_ruin_alias_still_vetoes_without_a_canonical_tier(self):
        # With NO canonical effect_risk_tier the NON-CANONICAL alias is honoured, so the veto is not
        # lost during the alias deprecation window.
        request = ApprovalRequest(operation="read", ruin_class="RUIN")
        self.assertEqual(human_gate_required(request).route, "ARTIFACT:RUIN_HARD_VETO")




if __name__ == "__main__":
    unittest.main()
