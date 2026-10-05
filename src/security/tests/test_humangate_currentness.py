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
    APPROVAL_BASIS_FRAME, APPROVAL_DECISION_BASIS_FIELDS, AUTHN_ASSURANCE_CLASSES,
    AUTHN_ASSURANCE_ORDER, DECISION_EXECUTABLE_STATES, DOMAIN_FRAME, JCS_PROFILE, _CLASS_ABSENT,
    _CLASS_MALFORMED, _CLASS_VALID, _classify_domain, _required_authn_floor, ApprovalDecision,
    ApprovalRequest, ApprovalToken, HumanGateDecision, JCSError, NonceLedger, VerificationContext,
    approval_basis_hash, approval_decision_basis_hash, canonical_payload_bytes, jcs_dumps,
    verify_approval_token,
)
from security.rights import (  # noqa: E402
    EFFECT_RISK_TIERS, HIGH_RISK_ACTIONS, HumanGateBypassAttempt, HumanGateRoute, RightsDenied,
    RightsScope,
    assert_credential_scope, assert_human_gate_satisfied, check_rights, currentness_required,
    human_gate_required, human_gate_route,
)

NOW = "2026-06-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"
COMMIT = "2026-06-01T00:30:00Z"

DIGEST = "a" * 64
SIGNATURE = "A" * 86

# WO-SWOF-W2-R007: the LITERAL frozen PI06 15.5 golden vector. The expected value is an
# independent source-derived constant for the six fields below and is NOT produced by calling
# `approval_basis_hash`; a regression in the byte recipe cannot move both sides together.
R007_SIX_FIELDS = (DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0")
R007_FROZEN_APPROVAL_BASIS = (
    "2a868198e40141f4ccfdcf5767fcb4f5950a3c241fc04b32de7d173cb79e6992"
)
# The recipe that ADDED five inter-field newline bytes; the frozen source rejects it.
R007_OLD_BASIS = "b7965468fb4b11f51c44342d8aefe92c2120a8eb5ed648678f3c09d85eb91080"

# WO-SWOF-W2-R007: the LITERAL frozen ApprovalDecisionBasisV1 JCS digest. Independent source
# constant for the decision fixture below; it does NOT call the helper under test.
R007_APPROVAL_DECISION_BASIS = (
    "9adf0095a78dd6244d3a9190b022ac611b0f73a7730b760fb352678da0c7b3c1"
)

# WO-SWOF-W2-R004: the signature is a REAL Ed25519 signature. The TEST key never leaves this
# module; the library performs the verification against a public key resolved by the registered
# resolver, and only the resolver supplies key material.
_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_PUBLIC_BYTES = _PRIVATE_KEY.public_key().public_bytes_raw()

BASIS = approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0")
# WO-SWOF-W2-R007: the LITERAL frozen 15.5 approval basis for the fixture request, whose
# `decision_basis_hash` is R007_APPROVAL_DECISION_BASIS. Source-derived, not helper-derived.
R007_FIXTURE_APPROVAL_BASIS = (
    "3c8dfb2d5ac6c678053550795acf87223d8b8df15816c4b5357aa990278b2c80"
)


def _sign_payload(payload: bytes) -> str:
    """Ed25519 over the canonical bytes, base64url WITHOUT padding -> exactly 86 characters."""
    return base64.urlsafe_b64encode(_PRIVATE_KEY.sign(payload)).decode("ascii").rstrip("=")


def _honest_registry(issuer_id, key_id, key_generation):
    """A contract-correct key RESOLVER: returns the raw Ed25519 public key bytes for the key."""
    if (issuer_id, key_id, key_generation) != ("issuer-1", "key-1", 3):
        return None
    return _PUBLIC_BYTES


def _authority_policy(decision_authority_class, required_authority):
    """A TEST owner policy: the request names its own required HA class; only that class is enough.

    This library defines NO HA ordering. The test policy is deliberately literal: the decision's
    authority class must equal the class the request declares as required.
    """
    return decision_authority_class == required_authority


def _current_decision(**overrides):
    """The canonical CURRENT HumanGateDecision fixture the owner resolver would return."""
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
    return replace(decision, decision_basis_hash=R007_APPROVAL_DECISION_BASIS)


def _decision_registry(mapping=None):
    """An owner-callable resolver: a mapping of decision_id -> current decision, else None."""
    decisions = dict(mapping) if mapping is not None else {"dec-1": _current_decision()}
    return lambda decision_id: decisions.get(decision_id)


def _request_resolver(trusted):
    """The OWNER-CALLABLE trusted request resolver (R6): the CURRENT request for its id, else None.

    Mirrors `_decision_registry`: the resolver is keyed by `request_id`, so a stale/superseded id
    that does not match the trusted request yields None (fail closed), never a wrong request.
    """
    return lambda request_id: trusted if trusted.request_id == request_id else None


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

    It MEETS the frozen PI06 minimum policy (P3 / MEDIUM / clause {HA1} / AAC1), so the JCS /
    Ed25519 / time / nonce / generation / basis / lineage cases exercise the mechanics rather than
    being shadowed by the new floor. RELEASE-specific cases use `_canonical_release_request`.
    """
    fields = dict(
        subject="svc-a", subject_hash=DIGEST, semantic_version="1.0.0", actor="human:alice",
        operation="ACT-EXTERNAL-WRITE-REV", target_system="swof", resource=("artifact:app",),
        environment="prod", purpose_ref="purpose:release", scope=("release",), data_class="INTERNAL",
        effect_digest=DIGEST, consumer_audience_hash=DIGEST, effect_risk_tier="MEDIUM",
        permission_class="P3", autonomy_tier="T2", required_authority="HA1",
        required_authn_assurance="AAC2", adapter_kind="canonical",
        rollback_ref="rollback:1", independent_checker_required=False, ruin_class="NONE",
        request_id="req-1", decision_id="dec-1", decision_basis_hash=R007_APPROVAL_DECISION_BASIS,
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
    """R8: a canonical-valid RELEASE token binding `_canonical_release_request`."""
    fields = dict(
        operation="release", authn_assurance_class="AAC3", independent_checker_required=True,
        independent_checker_evidence_ref="evidence:checker-1", rollback_ref="rollback:1",
    )
    fields.update(overrides)
    return _valid_token(**fields)


def _release_ctx(**overrides):
    fields = dict(
        commit_time=COMMIT,
        expected_consumer_audience_hash=DIGEST,
        trusted_key_registry=_honest_registry,
        nonce_ledger=NonceLedger(), max_reauth_age_seconds=3600,
        # WO-SWOF-W2-R007: the positive control injects a canonical CURRENT decision and an
        # owner policy that is sufficient for the request's declared HA requirement.
        decision_resolver=_decision_registry(),
        authority_policy=_authority_policy,
        # R6 (F-W2R5-EXT-001): the trusted current request of the default fixture. The plain
        # fixture request is its own trusted current request; a case that wants a DIVERGENT trusted
        # request overrides this seam explicitly.
        request_resolver=_request_resolver(_release_request()),
    )
    fields.update(overrides)
    return VerificationContext(**fields)


def _verify(token_over=None, request_over=None, ctx_over=None):
    request = _release_request(**(request_over or {}))
    ctx_fields = dict(ctx_over or {})
    # R6 (F-W2R5-EXT-001): every pre-R6 case keeps its original meaning by making the caller request
    # its own TRUSTED current request. A case that needs a divergent trusted request overrides
    # `request_resolver` explicitly through `ctx_over`.
    ctx_fields.setdefault("request_resolver", _request_resolver(request))
    return verify_approval_token(
        _valid_token(**(token_over or {})), request, _release_ctx(**ctx_fields))

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
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        # R7: a benign NONE route now needs the TRUSTED current request to resolve.
        self.assertIsNone(assert_human_gate_satisfied(
            route, "", request=request,
            ctx=_release_ctx(request_resolver=_request_resolver(request))))

    def test_r2_11_p3_request_with_bare_string_approval_needs_a_typed_token(self):
        route = human_gate_route("release")
        request = _release_request(effect_risk_tier="LOW", permission_class="P3")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            assert_human_gate_satisfied(route, "HG-2026-0007", request=request, ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "DENY_P3_TOKEN_REQUIRED")

    def test_r2_12_p3_request_with_a_valid_typed_token_passes(self):
        route = human_gate_route("release")
        request = _release_request(effect_risk_tier="HIGH", permission_class="P3")
        self.assertIsNone(assert_human_gate_satisfied(
            route, _valid_token(), requesting_actor="human:dave", request=request,
            ctx=_release_ctx(request_resolver=_request_resolver(request))))


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
            ctx=_release_ctx(request_resolver=_request_resolver(request))))

    def test_r4_d1_06_p2_benign_operation_without_token_is_allowed(self):
        request = _release_request(operation="read", effect_risk_tier="LOW", permission_class="P2")
        self.assertEqual(human_gate_required(request).route, "NONE")
        self.assertFalse(human_gate_required(request).required)
        # R7: the benign return needs the matching TRUSTED current request resolver.
        self.assertIsNone(assert_human_gate_satisfied(
            human_gate_route("read"), "", request=request,
            ctx=_release_ctx(request_resolver=_request_resolver(request))))

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
        # WO-SWOF-W2-R007: PI06 15.5 is DIRECT concatenation with exactly ONE newline (the one
        # inside the frame). The old `"\n".join` recipe is asserted UNEQUAL, not reproduced.
        import hashlib
        frame = APPROVAL_BASIS_FRAME
        direct_material = frame + ("".join(R007_SIX_FIELDS)).encode("utf-8")
        old_material = frame + ("\n".join(R007_SIX_FIELDS)).encode("utf-8")
        self.assertEqual(
            approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0"),
            hashlib.sha256(direct_material).hexdigest())
        self.assertEqual(
            approval_basis_hash(DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, "1.0"),
            R007_FROZEN_APPROVAL_BASIS)
        self.assertNotEqual(hashlib.sha256(old_material).hexdigest(),
                            R007_FROZEN_APPROVAL_BASIS)
        self.assertEqual(hashlib.sha256(old_material).hexdigest(), R007_OLD_BASIS)
        self.assertNotEqual(R007_OLD_BASIS, R007_FROZEN_APPROVAL_BASIS)
        self.assertEqual(BASIS, R007_FROZEN_APPROVAL_BASIS)


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
        self.assertEqual(_verify(request_over={"operation": "read", "effect_risk_tier": "LOW",
                                               "permission_class": "P2",
                                               "ruin_class": "RUIN"},
                                  token_over={"operation": "read"}).code,
                         "APPROVE_BASIS_SATISFIED")

    def test_r5_11_legacy_ruin_alias_still_vetoes_without_a_canonical_tier(self):
        # With NO canonical effect_risk_tier the NON-CANONICAL alias is honoured, so the veto is not
        # lost during the alias deprecation window.
        request = ApprovalRequest(operation="read", ruin_class="RUIN")
        self.assertEqual(human_gate_required(request).route, "ARTIFACT:RUIN_HARD_VETO")




# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R006 (R6): the OPERATION / ACTION_CLASS axis fails CLOSED. DOC-03 L867 makes `operation`
# a required field over a known action enum and L874 does the same for `action_class`: an operation
# that cannot be classified is an UNKNOWN_RUIN-classed outcome and SAFE-STOPS rather than passing
# ungated. L396-410 classifies on the EFFECT, so a benign-looking name never buys a weaker route.
# ---------------------------------------------------------------------------------------------
class TestCanonicalOperationAxisR6(unittest.TestCase):

    UNKNOWN_OPERATIONS = (
        "definitely-not-a-known-operation", "unknown_action", "delete", "merge",
        "create_or_update_file",
    )

    def _seam(self, request, approval="", **kwargs):
        route = human_gate_required(request)
        return assert_human_gate_satisfied(route, approval, request=request, **kwargs)

    def test_r6_01_unknown_operation_safe_stops_at_the_seam(self):
        for operation in self.UNKNOWN_OPERATIONS:
            with self.subTest(operation=operation):
                request = _release_request(operation=operation)
                route = human_gate_required(request)
                self.assertEqual((route.required, route.route), (True, "ARTIFACT:RUIN_SAFE_STOP"))
                self.assertEqual(route.authority_edge, "RUIN:SAFE_STOP")
                with self.assertRaises(HumanGateBypassAttempt) as caught:
                    self._seam(request, "", ctx=_release_ctx())
                self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_r6_02_unknown_operation_is_not_rescued_by_a_valid_token(self):
        request = _release_request(operation="definitely-not-a-known-operation")
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request, _valid_token(), requesting_actor="human:dave", ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "SAFE_STOP_UNKNOWN_RUIN")

    def test_r6_03_empty_and_non_string_operation_safe_stop(self):
        for operation in ("", None, 17):
            with self.subTest(operation=repr(operation)):
                request = _release_request(operation=operation)
                route = human_gate_required(request)
                self.assertTrue(route.required)
                self.assertEqual(route.route, "ARTIFACT:RUIN_SAFE_STOP")

    def test_r6_04_known_benign_operation_is_the_positive_control(self):
        for operation in ("read", "ACT-READ-LOCAL"):
            for tier in ("LOW", "MEDIUM"):
                for permission in ("P0", "P1", "P2"):
                    with self.subTest(operation=operation, tier=tier, permission=permission):
                        request = _release_request(operation=operation, effect_risk_tier=tier,
                                                   permission_class=permission)
                        self.assertFalse(human_gate_required(request).required)
                        self.assertEqual(human_gate_required(request).route, "NONE")
                        # R7: the benign return needs the matching TRUSTED current request.
                        self.assertIsNone(self._seam(request, "", ctx=_release_ctx(
                            request_resolver=_request_resolver(request))))

    def test_r6_05_known_high_risk_operation_still_gates_with_its_edge(self):
        for operation in sorted(HIGH_RISK_ACTIONS):
            with self.subTest(operation=operation):
                request = _release_request(operation=operation, effect_risk_tier="LOW",
                                           permission_class="P2")
                route = human_gate_required(request)
                self.assertTrue(route.required)
                self.assertEqual(route.authority_edge, "HUMAN_GATE:%s" % operation)
                # A LOW/P2 classification does not by itself demand a typed token, but the route is
                # gated by the named high-risk operation and refuses a non-canonical approval.
                with self.assertRaises(HumanGateBypassAttempt) as caught:
                    self._seam(request, "", ctx=_release_ctx())
                self.assertEqual(str(caught.exception), "NOT_A_CANONICAL_APPROVAL_TOKEN")

    def test_r6_06_consequential_canonical_class_tightens_a_benign_asserted_tier(self):
        request = _release_request(operation="ACT-DELETE-IRREV", effect_risk_tier="LOW",
                                   permission_class="P2")
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertEqual(route.route, "ARTIFACT:HUMAN_GATE")
        self.assertEqual(route.authority_edge, "HUMAN_GATE:ACT-DELETE-IRREV")
        # LOW/P2 does not by itself force a typed token, so the refusal is the code for a
        # non-canonical approval; what matters is that the tightened route REFUSES the empty string
        # instead of passing, because the canonical class named by the effect is consequential.
        with self.assertRaises(HumanGateBypassAttempt) as caught:
            self._seam(request, "", ctx=_release_ctx())
        self.assertEqual(str(caught.exception), "NOT_A_CANONICAL_APPROVAL_TOKEN")

    def test_r6_07_unknown_operation_still_safe_stops_with_a_ruin_classification(self):
        request = _release_request(operation="unknown_action", effect_risk_tier="RUIN")
        self.assertEqual(human_gate_required(request).route, "ARTIFACT:RUIN_HARD_VETO")
        request = _release_request(operation="unknown_action", effect_risk_tier="LOW",
                                   permission_class="P2", autonomy_tier="T3")
        route = human_gate_required(request)
        self.assertTrue(route.required)
        self.assertEqual(route.route, "ARTIFACT:RUIN_SAFE_STOP")

    def test_r6_08_route_shim_and_predicate_agree_on_the_unknown_operation(self):
        for operation in self.UNKNOWN_OPERATIONS:
            with self.subTest(operation=operation):
                shim = human_gate_route(operation)
                predicate = human_gate_required(ApprovalRequest(operation=operation))
                self.assertEqual((shim.required, shim.route), (predicate.required, predicate.route))
                self.assertEqual(shim.route, "ARTIFACT:RUIN_SAFE_STOP")



# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R007. A. Exact frozen 15.5 basis bytes.
# ---------------------------------------------------------------------------------------------
class TestExactBasisBytesR007(unittest.TestCase):

    def test_r007_a1_literal_golden_vector(self):
        # A1: the expected digest is an independent LITERAL source constant; this test does NOT
        # call approval_basis_hash to build its expected value.
        import hashlib
        independent_material = APPROVAL_BASIS_FRAME + "".join(R007_SIX_FIELDS).encode("utf-8")
        self.assertEqual(hashlib.sha256(independent_material).hexdigest(),
                         R007_FROZEN_APPROVAL_BASIS)
        self.assertEqual(approval_basis_hash(*R007_SIX_FIELDS), R007_FROZEN_APPROVAL_BASIS)

    def test_r007_a2_old_newline_recipe_is_rejected(self):
        import hashlib
        old_material = APPROVAL_BASIS_FRAME + "\n".join(R007_SIX_FIELDS).encode("utf-8")
        old_digest = hashlib.sha256(old_material).hexdigest()
        self.assertEqual(old_digest, R007_OLD_BASIS)
        self.assertNotEqual(old_digest, R007_FROZEN_APPROVAL_BASIS)
        decision = _verify(token_over={"approval_basis_hash": R007_OLD_BASIS})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_APPROVAL_BASIS"))

    def test_r007_a3_wrong_basis_hash_is_denied(self):
        decision = _verify(token_over={"approval_basis_hash": "b" * 64})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_APPROVAL_BASIS"))


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R007. B. Current authority + HumanGateDecision lineage.
# ---------------------------------------------------------------------------------------------
class TestAuthorityDecisionLineageR007(unittest.TestCase):

    def _resolved(self, **decision_overrides):
        return _decision_registry({"dec-1": _current_decision(**decision_overrides)})

    def test_r007_b1_insufficient_authority_is_denied(self):
        decision = _verify(ctx_over={"decision_resolver": self._resolved(authority_class="HA2")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_INSUFFICIENT_AUTHORITY"))

    def test_r007_b2_unknown_authority_class_is_denied(self):
        decision = _verify(ctx_over={"decision_resolver": self._resolved(authority_class="HA9")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_INSUFFICIENT_AUTHORITY"))

    def test_r007_b3_revoked_superseded_or_non_executable_is_denied(self):
        self.assertEqual(DECISION_EXECUTABLE_STATES, ("APPROVE",))
        for over in ({"revoked": True}, {"superseded": True}, {"decision": "DENY"},
                     {"decision": "SAFE_STOP"}, {"decision": "VETO"}):
            with self.subTest(over=over):
                decision = _verify(ctx_over={"decision_resolver": self._resolved(**over)})
                self.assertEqual((decision.ok, decision.code),
                                 (False, "DENY_DECISION_NOT_EXECUTABLE"))

    def test_r007_b3b_malformed_decided_at_is_denied(self):
        decision = _verify(ctx_over={"decision_resolver": self._resolved(decided_at="not-a-time")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_DECISION_NOT_EXECUTABLE"))

    def test_r007_b4_nonexistent_decision_id_is_denied(self):
        unknown = _verify(ctx_over={"decision_resolver": _decision_registry({})})
        self.assertEqual((unknown.ok, unknown.code), (False, "DENY_DECISION_UNRESOLVED"))
        absent = _verify(ctx_over={"decision_resolver": None})
        self.assertEqual((absent.ok, absent.code), (False, "DENY_DECISION_UNRESOLVED"))
        lookalike = _verify(ctx_over={"decision_resolver": lambda decision_id: object()})
        self.assertEqual((lookalike.ok, lookalike.code), (False, "DENY_DECISION_UNRESOLVED"))

    def test_r007_b5_decision_bound_to_another_request_is_denied(self):
        decision = _verify(ctx_over={"decision_resolver": self._resolved(request_id="req-other")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_DECISION_REQUEST_MISMATCH"))

    def test_r007_b6_decision_id_not_matching_the_token_is_denied(self):
        decision = _verify(ctx_over={"decision_resolver": self._resolved(decision_id="dec-other")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_DECISION_TOKEN_MISMATCH"))

    def test_r007_b7_caller_basis_does_not_match_recomputed_jcs_basis(self):
        decision = _verify(request_over={"decision_basis_hash": "c" * 64})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_DECISION_BASIS_MISMATCH"))
        # The recomputable basis is the frozen field set EXCLUDING the digest itself.
        self.assertNotIn("decision_basis_hash", APPROVAL_DECISION_BASIS_FIELDS)

    def test_r007_b8_current_decision_and_sufficient_authority_pass(self):
        decision = _verify()
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r007_b9_absent_authority_policy_fails_closed(self):
        # Do NOT invent an HA ordering: an absent policy seam is TEMP-CLOSED, not a guess.
        decision = _verify(ctx_over={"authority_policy": None})
        self.assertEqual((decision.ok, decision.code), (False, "TEMP_CLOSED_AUTHORITY_RESOLUTION"))

    def test_r007_b10_request_without_required_authority_is_denied(self):
        # R8: dropping the declaration no longer covers a PI06 clause, so the floor refuses first.
        decision = _verify(request_over={"required_authority": ""})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_POLICY_FLOOR"))

    def test_r007_b11_decision_authn_downgrade_is_denied(self):
        decision = _verify(
            ctx_over={"decision_resolver": self._resolved(authn_assurance_class="AAC1")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R007. C. Canonical signed sets.
# ---------------------------------------------------------------------------------------------
class TestCanonicalSignedSetsR007(unittest.TestCase):

    def _schema_properties(self):
        path = Path(__file__).resolve().parents[3] / "schemas" / "security" / "approval_token.schema.json"
        return json.loads(path.read_text(encoding="utf-8"))["properties"]

    def test_r007_c1_resource_permutation_is_one_representation(self):
        first = _valid_token(resource=("artifact:a", "artifact:b"))
        second = _valid_token(resource=("artifact:b", "artifact:a"))
        self.assertEqual(canonical_payload_bytes(first), canonical_payload_bytes(second))

    def test_r007_c2_scope_permutation_is_one_representation(self):
        first = _valid_token(scope=("scope:b", "scope:a"))
        second = _valid_token(scope=("scope:a", "scope:b"))
        self.assertEqual(canonical_payload_bytes(first), canonical_payload_bytes(second))

    def test_r007_c3_framed_digest_is_invariant_under_set_permutation(self):
        import hashlib
        first = _valid_token(resource=("artifact:a", "artifact:b"), scope=("s2", "s1"))
        second = _valid_token(resource=("artifact:b", "artifact:a"), scope=("s1", "s2"))
        self.assertEqual(hashlib.sha256(canonical_payload_bytes(first)).hexdigest(),
                         hashlib.sha256(canonical_payload_bytes(second)).hexdigest())

    def test_r007_c3b_permuted_token_and_request_agree(self):
        request = _release_request(resource=("artifact:b", "artifact:a"), scope=("s2", "s1"))
        token = _valid_token(resource=("artifact:a", "artifact:b"), scope=("s1", "s2"))
        decision = verify_approval_token(token, request, _release_ctx())
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r007_c4_duplicate_atom_is_denied(self):
        for over in ({"resource": ("artifact:app", "artifact:app")},
                     {"scope": ("release", "release")}):
            with self.subTest(over=over):
                unsigned = _valid_token(signature=SIGNATURE, **over)
                with self.assertRaises(JCSError):
                    canonical_payload_bytes(unsigned)
                decision = verify_approval_token(unsigned, _release_request(), _release_ctx())
                self.assertFalse(decision.ok)

    def test_r007_c5_malformed_atom_is_denied(self):
        for over in ({"resource": ("artifact:app", "   ")}, {"scope": ("release", "")},
                     {"resource": ("artifact:app", 17)}, {"scope": "not-a-set"}):
            with self.subTest(over=over):
                unsigned = _valid_token(signature=SIGNATURE, **over)
                with self.assertRaises(JCSError):
                    canonical_payload_bytes(unsigned)
                decision = verify_approval_token(unsigned, _release_request(), _release_ctx())
                self.assertFalse(decision.ok)

    def test_r007_c6_resource_annotation_is_set(self):
        self.assertEqual(self._schema_properties()["resource"]["x-swof-collection-semantics"],
                         "set")

    def test_r007_c7_scope_annotation_is_set(self):
        self.assertEqual(self._schema_properties()["scope"]["x-swof-collection-semantics"], "set")

    def test_r007_c8_decision_reason_codes_are_a_canonical_set(self):
        first = _current_decision(reason_codes=("z-code", "a-code"))
        second = _current_decision(reason_codes=("a-code", "z-code"))
        self.assertEqual(approval_decision_basis_hash(first),
                         approval_decision_basis_hash(second))

    def test_r007_c9_decision_basis_is_the_frozen_literal(self):
        self.assertEqual(approval_decision_basis_hash(_current_decision()),
                         R007_APPROVAL_DECISION_BASIS)



# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R008 (R4). The authn-assurance floor is POLICY-BOUND at the request, not a
# hard-coded implementation default. Every expected value below is derived from the frozen
# canonical domain (PI06 DOC-03 14.R / 15.2), NOT from the helper under test.
# ---------------------------------------------------------------------------------------------
class TestRequiredAuthnFloorResolutionR008(unittest.TestCase):
    """The floor RESOLVER returns the EXACT validated request floor - never a default."""

    def test_r008_floor_domain_is_the_canonical_aac_triple(self):
        self.assertEqual(AUTHN_ASSURANCE_CLASSES, ("AAC1", "AAC2", "AAC3"))
        self.assertEqual(AUTHN_ASSURANCE_ORDER, {"AAC1": 1, "AAC2": 2, "AAC3": 3})

    def test_r008_floor_returns_each_canonical_request_value_exactly(self):
        for floor in ("AAC1", "AAC2", "AAC3"):
            with self.subTest(floor=floor):
                self.assertEqual(
                    _required_authn_floor(_release_request(required_authn_assurance=floor)), floor)

    def test_r008_missing_validated_floor_is_none_not_a_default(self):
        # The removed constant was AAC2; a MISSING floor must never resolve to it (or any value).
        for missing in ("", None, "   "):
            with self.subTest(missing=repr(missing)):
                self.assertIsNone(
                    _required_authn_floor(_release_request(required_authn_assurance=missing)))

    def test_r008_malformed_validated_floor_is_none_not_a_default(self):
        for malformed in ("AAC9", "aac2", 2, ("AAC2",), "AAC2 "):
            with self.subTest(malformed=repr(malformed)):
                self.assertIsNone(
                    _required_authn_floor(_release_request(required_authn_assurance=malformed)))

    def test_r008_floor_classification_distinguishes_absent_valid_and_malformed(self):
        self.assertEqual(_classify_domain(None, AUTHN_ASSURANCE_CLASSES), (_CLASS_ABSENT, None))
        self.assertEqual(_classify_domain("AAC2", AUTHN_ASSURANCE_CLASSES),
                         (_CLASS_VALID, "AAC2"))
        self.assertEqual(_classify_domain("AAC9", AUTHN_ASSURANCE_CLASSES),
                         (_CLASS_MALFORMED, "AAC9"))

    def test_r008_no_request_controlled_adapter_can_substitute_a_floor(self):
        # R5 (SWOF-W2-CLOSURE-R5): the `adapter_kind` compatibility selector is REMOVED from the
        # canonical verifier. A missing/malformed canonical floor fails closed (None) regardless
        # of any request-controlled adapter kind; CRITICAL/AAC3 can never be under-enforced to AAC2.
        for kind in ("canonical", "local_adapter", "something-else"):
            with self.subTest(kind=kind):
                self.assertIsNone(_required_authn_floor(_release_request(
                    required_authn_assurance="", adapter_kind=kind)))
        # A present canonical floor is returned EXACTLY and is the ONLY floor source.
        self.assertEqual(
            _required_authn_floor(_release_request(
                required_authn_assurance="AAC3", adapter_kind="local_adapter")), "AAC3")


class TestPolicyBoundAuthnFloorR008(unittest.TestCase):
    """A1-A10: floor vs decision vs token, holding authority/lineage constant.

    The request fixture always declares `required_authority="HA3"`, the resolved decision carries
    `authority_class="HA3"` and an EXACT token/decision/request lineage; the resolution sits BEFORE
    the signature check, so these cases exercise the authn(DECISION)/authn(TOKEN) axes by themselves.
    """

    def _resolved(self, **decision_overrides):
        return _decision_registry({"dec-1": _current_decision(**decision_overrides)})

    def test_r008_a1_request_aac1_decision_aac1_may_pass(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC1"},
                           token_over={"authn_assurance_class": "AAC1"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC1")})
        self.assertTrue(decision.ok, decision.code)

    def test_r008_a2_request_aac2_decision_aac1_is_denied(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC2"},
                           token_over={"authn_assurance_class": "AAC1"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC1")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))

    def test_r008_a3_request_aac2_decision_aac2_may_pass(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC2"},
                           token_over={"authn_assurance_class": "AAC2"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC2")})
        self.assertTrue(decision.ok, decision.code)

    def test_r008_a4_request_aac3_decision_aac2_is_denied(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC3"},
                           token_over={"authn_assurance_class": "AAC2"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC2")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))

    def test_r008_a5_request_aac3_decision_aac3_may_pass(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC3"},
                           token_over={"authn_assurance_class": "AAC3"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC3")})
        self.assertTrue(decision.ok, decision.code)

    def test_r008_a6_missing_request_floor_fails_closed_never_implicit_aac2(self):
        # The decision and token are BOTH AAC2 - exactly what the removed default demanded - so an
        # implicit AAC2 would let this pass. It must be DENY_AUTHN instead.
        for missing in ("", None):
            with self.subTest(missing=repr(missing)):
                decision = _verify(request_over={"required_authn_assurance": missing},
                                   token_over={"authn_assurance_class": "AAC2"},
                                   ctx_over={"decision_resolver": self._resolved(
                                       authn_assurance_class="AAC2")})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_POLICY_FLOOR"))

    def test_r008_a7_malformed_or_unknown_floor_is_denied(self):
        for malformed in ("AAC9", "aac2", "AAC0", 2):
            with self.subTest(malformed=repr(malformed)):
                decision = _verify(request_over={"required_authn_assurance": malformed},
                                   ctx_over={"decision_resolver": self._resolved(
                                       authn_assurance_class="AAC3")})
                self.assertEqual((decision.ok, decision.code), (False, "DENY_POLICY_FLOOR"))

    def test_r008_a8_critical_request_aac3_decision_and_token_aac2_is_denied(self):
        # A KNOWN benign operation carries no PI06 clause, so this isolates the AUTHN axis: the
        # AAC3 floor + a decision/token AAC2 still deny. (A sufficient HA1 decision is present.)
        request = _verify(request_over={"operation": "read", "effect_risk_tier": "CRITICAL",
                                        "required_authn_assurance": "AAC3"},
                          token_over={"operation": "read", "authn_assurance_class": "AAC2"},
                          ctx_over={"decision_resolver": self._resolved(
                              authority_class="HA1", authn_assurance_class="AAC2")})
        self.assertEqual((request.ok, request.code), (False, "DENY_AUTHN"))

    def test_r008_a9_critical_request_aac3_decision_and_token_aac3_proceeds(self):
        decision = _verify(request_over={"operation": "read", "effect_risk_tier": "CRITICAL",
                                         "required_authn_assurance": "AAC3"},
                           token_over={"operation": "read", "authn_assurance_class": "AAC3"},
                           ctx_over={"decision_resolver": self._resolved(
                               authority_class="HA1", authn_assurance_class="AAC3")})
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r008_a10_sufficient_authority_does_not_compensate_for_weak_authn(self):
        # A top-of-domain HA5 decision still cannot rescue an AAC downgrade: the axes are independent.
        decision = _verify(request_over={"required_authority": "HA1",
                                         "required_authn_assurance": "AAC3"},
                           token_over={"authn_assurance_class": "AAC2"},
                           ctx_over={"decision_resolver": self._resolved(
                               authority_class="HA1", authn_assurance_class="AAC2")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))


class TestTokenAndDecisionAuthnFloorR008(unittest.TestCase):
    """B1-B7: the signed token and the owner-resolved decision must each meet the request floor."""

    def _resolved(self, **decision_overrides):
        return _decision_registry({"dec-1": _current_decision(**decision_overrides)})

    def test_r008_b1_decision_meets_floor_but_token_below_floor_is_denied(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC2"},
                           token_over={"authn_assurance_class": "AAC1"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC2")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))

    def test_r008_b2_token_meets_floor_but_decision_below_floor_is_denied(self):
        decision = _verify(request_over={"required_authn_assurance": "AAC2"},
                           token_over={"authn_assurance_class": "AAC2"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC1")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_AUTHN"))

    def test_r008_b3_both_meet_the_exact_request_floor_an_aac1_request_proceeds(self):
        # An AAC1 request is NOT force-upgraded to AAC3: the exact floor AAC1 is satisfiable.
        decision = _verify(request_over={"required_authn_assurance": "AAC1"},
                           token_over={"authn_assurance_class": "AAC1"},
                           ctx_over={"decision_resolver": self._resolved(
                               authn_assurance_class="AAC1")})
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    def test_r008_b4_absent_decision_resolver_is_deny_decision_unresolved(self):
        decision = _verify(ctx_over={"decision_resolver": None})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_DECISION_UNRESOLVED"))

    def test_r008_b5_absent_authority_policy_is_temp_closed(self):
        decision = _verify(ctx_over={"authority_policy": None})
        self.assertEqual((decision.ok, decision.code), (False, "TEMP_CLOSED_AUTHORITY_RESOLUTION"))

    def test_r008_b6_valid_signature_with_insufficient_authority_is_denied(self):
        # The token IS genuinely signed over the framed canonical bytes; authority still refuses it.
        decision = _verify(ctx_over={"decision_resolver": self._resolved(authority_class="HA2")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_INSUFFICIENT_AUTHORITY"))

    def test_r008_b7_decision_bound_to_another_request_is_denied(self):
        decision = _verify(ctx_over={"decision_resolver": self._resolved(request_id="req-other")})
        self.assertEqual((decision.ok, decision.code), (False, "DENY_DECISION_REQUEST_MISMATCH"))


# ---------------------------------------------------------------------------------------------
# WO-SWOF-W2-R006R (R6). Branch A: the trusted request boundary (F-W2R5-EXT-001).
# The policy-owned request fields (required_authn_assurance, effect_risk_tier, permission_class,
# autonomy_tier, required_authority, ...) are DERIVED by policy owners, never caller choice. The
# verifier pins the caller request to the OWNER-INJECTED `request_resolver` and reads the authn
# floor from the TRUSTED request, so a caller can never declare its way to a weaker floor.
# ---------------------------------------------------------------------------------------------
class TestR6TrustedRequestBoundary(unittest.TestCase):
    """A1-A13: a caller-declared policy downgrade is refused; a matching trusted request passes."""

    def _resolved(self, **decision_overrides):
        return _decision_registry({"dec-1": _current_decision(**decision_overrides)})

    def _denied(self, expected_code, request_over=None, trusted=None, ctx_over=None,
                token_over=None):
        request = _release_request(**(request_over or {}))
        fields = dict(ctx_over or {})
        if trusted is not None:
            fields["request_resolver"] = _request_resolver(trusted)
        decision = _verify(token_over=token_over, request_over=request_over, ctx_over=fields)
        self.assertEqual((decision.ok, decision.code), (False, expected_code))
        return request

    # A1: a CRITICAL/AAC3 trusted request cloned as CRITICAL/AAC2 (same binding) is refused.
    def test_a1_trusted_critical_aac3_caller_clone_aac2_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"effect_risk_tier": "CRITICAL", "required_authn_assurance": "AAC2"},
            trusted=_release_request(effect_risk_tier="CRITICAL",
                                     required_authn_assurance="AAC3"))

    # A2: a P4/AAC3 trusted request cloned as P4/AAC2 is refused.
    def test_a2_trusted_p4_aac3_caller_clone_aac2_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"permission_class": "P4", "required_authn_assurance": "AAC2"},
            trusted=_release_request(permission_class="P4", required_authn_assurance="AAC3"))

    # A3: a protected P5/AAC3 trusted request cloned as P5/AAC2 is refused.
    def test_a3_trusted_protected_p5_aac3_caller_clone_aac2_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"permission_class": "P5", "required_authn_assurance": "AAC2"},
            trusted=_release_request(permission_class="P5", required_authn_assurance="AAC3"))

    # A4: the caller lowers effect_risk_tier below the trusted current value.
    def test_a4_caller_lowers_effect_risk_tier_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"effect_risk_tier": "LOW", "required_authn_assurance": "AAC3"},
            trusted=_release_request(effect_risk_tier="CRITICAL",
                                     required_authn_assurance="AAC3"))

    # A5: the caller lowers the permission_class below the trusted current value.
    def test_a5_caller_lowers_permission_class_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"permission_class": "P2"},
            trusted=_release_request(permission_class="P3"))

    # A6: the caller lowers the autonomy_tier below the trusted current value.
    def test_a6_caller_lowers_autonomy_tier_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"autonomy_tier": "T2"},
            trusted=_release_request(autonomy_tier="T3"))

    # A7: the caller lowers the required_authority below the trusted current value.
    def test_a7_caller_lowers_required_authority_is_policy_mismatch(self):
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"required_authority": "HA3"},
            trusted=_release_request(required_authority="HA5"))

    # A8: the gate demanded a trusted resolver; an ABSENT one on a gated (canonical-floor) path
    # FAILS CLOSED as DENY_REQUEST_UNRESOLVED, never treated as "skip".
    def test_a8_missing_trusted_request_resolver_is_deny_request_unresolved(self):
        self._denied(
            "DENY_REQUEST_UNRESOLVED",
            request_over={"required_authn_assurance": "AAC3"},
            ctx_over={"request_resolver": None})

    # A9: a resolver that does not know the request_id resolves to None (absent/stale) -> DENY.
    def test_a9_trusted_request_not_found_is_deny_request_unresolved(self):
        self._denied(
            "DENY_REQUEST_UNRESOLVED",
            request_over={"required_authn_assurance": "AAC3"},
            trusted=_release_request(request_id="req-other", required_authn_assurance="AAC3"))

    # A10: a stale/superseded trusted request is refused: a foreign request_id resolves to None,
    # and a same-id request whose policy axis moved is a policy mismatch.
    def test_a10_stale_or_superseded_trusted_request_is_denied(self):
        self._denied(
            "DENY_REQUEST_UNRESOLVED",
            request_over={"required_authn_assurance": "AAC3"},
            trusted=_release_request(request_id="req-superseded",
                                     required_authn_assurance="AAC3"))
        self._denied(
            "DENY_REQUEST_POLICY_MISMATCH",
            request_over={"required_authn_assurance": "AAC3"},
            trusted=_release_request(effect_risk_tier="HIGH",
                                     required_authn_assurance="AAC3"))

    # A11: local_adapter with a missing floor is still DENY_AUTHN - no regression, and the removed
    # adapter selector can not substitute a floor.
    def test_a11_local_adapter_missing_floor_remains_deny_authn(self):
        # R8: an absent canonical floor is now a PI06 minimum-policy deny, not an implicit AAC2.
        self._denied(
            "DENY_POLICY_FLOOR",
            request_over={"adapter_kind": "local_adapter", "required_authn_assurance": ""})

    # A12: a resolver that returns the SAME request keeps the valid path sane.
    def test_a12_exact_trusted_request_with_valid_decision_and_token_is_approved(self):
        trusted = _release_request()
        decision = _verify(ctx_over={"request_resolver": _request_resolver(trusted)})
        self.assertEqual((decision.ok, decision.code), (True, "APPROVE_BASIS_SATISFIED"))

    # A13: legitimate AAC1/AAC2/AAC3 floors stay EXACT on a benign (LOW/P1) request - there is no
    # global force-upgrade to AAC3.
    def test_a13_exact_floors_remain_exact_on_a_benign_request(self):
        for floor in ("AAC1", "AAC2", "AAC3"):
            with self.subTest(floor=floor):
                decision = _verify(
                    request_over={"operation": "read", "effect_risk_tier": "LOW",
                                  "permission_class": "P1",
                                  "required_authn_assurance": floor},
                    token_over={"operation": "read", "authn_assurance_class": floor},
                    ctx_over={"decision_resolver": self._resolved(
                        authn_assurance_class=floor)})
                self.assertEqual((decision.ok, decision.code),
                                 (True, "APPROVE_BASIS_SATISFIED"))


if __name__ == "__main__":
    unittest.main()
