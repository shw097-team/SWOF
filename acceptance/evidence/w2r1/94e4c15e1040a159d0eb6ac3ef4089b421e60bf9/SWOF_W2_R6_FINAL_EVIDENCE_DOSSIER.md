# SWOF W2 R6 — Final Evidence Dossier

```yaml
repair_id: SWOF-W2-CLOSURE-R6
changeset: NARROW_REPAIR (Branch A)
adjudication: A_BLOCKER_CONFIRMED
source_candidate_sha: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
parent_source_sha: 02736d3eeb6156e9763f202fbd63fff430e9eeb7
parent_evidence_sha: a6ee9b5ce8b0b0905be4952c32b2ddd747929c25
claim_ceiling: READY_FOR_W2_EXTERNAL_RECHALLENGE only
```

## 1. Adjudication (Gate 2, read-only)

Equal-rank conflict between two R5 external reports resolved deterministically from frozen PI06
authority + exact source evidence (not by preference, chronology, test-count or LLM judgment):

- Report A (FAIL_CHALLENGE): `F-W2R5-EXT-001` caller-controlled canonical policy floor.
- Report B (TEMP_CLOSED_CHALLENGE): evidence-only; provenance deferred to W3.

**Resolution: `A_BLOCKER_CONFIRMED`.** On R5 `02736d3e`, `ApprovalRequest` is a public dataclass; the
verifier read the caller-declared `required_authn_assurance` directly as the floor (no trusted request
resolver), so a caller could declare a weaker floor on a CRITICAL/P4/P5 request. `_binding_errors` and
the decision basis did not pin the policy-owned fields. Frozen PI06 assigns `required_authn_assurance`
ownership to **policy**, and CRITICAL/P4/P5 require AAC3.

## 2. Product repair (Gate 3A, Branch A)

Smallest legal seam, mirroring `decision_resolver`/`authority_policy`:

- Added **third owner-injected seam** `request_resolver(request_id) -> current canonical ApprovalRequest`.
- Pre-authn-floor, the verifier resolves the trusted current request and pins the caller request on the
  policy-owned fields (`operation, operation_class, effect_risk_tier, permission_class, autonomy_tier,
  required_authority, required_authn_assurance, rollback_ref, independent_checker_required`).
- Absent resolver / unresolvable / foreign / stale request => `DENY_REQUEST_UNRESOLVED`.
- Any policy-field divergence => `DENY_REQUEST_POLICY_MISMATCH`.
- The authn floor and authority check read the **trusted** request, never the caller-declared one.

Constraints honoured: NO second policy engine, NO global AAC3 force-upgrade, NO adapter fallback.
Files: `src/security/humangate.py`, `src/security/tests/test_humangate_currentness.py`,
`src/security/tests/test_rights.py` (+273/−19).

## 3. Adversarial focused set (A1–A13)

`TestR6TrustedRequestBoundary` (13 tests) all PASS: trusted CRITICAL/P4/P5 + caller AAC2 clone => DENY;
caller lowers effect_risk_tier / permission_class / autonomy_tier / required_authority => DENY; missing
resolver / not-found / stale => fail-closed; local_adapter + missing floor => DENY_AUTHN (preserved);
exact trusted request + valid decision/token => PASS; exact AAC1/AAC2/AAC3 floors remain exact.

## 4. Regression (Gate 5)

- W1 = 113 (tests 16, fabric 21, knowledge 25, admission 17, profile 12, capability 22)
- W2 = 783 (security 421 incl. +13 R6 tests, effect 116, assurance 144, observability 102)
- grand_total = 896 (>=883, +13, no shrink), zero_denominator_roots = 0, all roots exit 0.

## 5. Fresh independent checker (Gate 6)

Fresh-context VERIFY_ONLY read-only, not the maker, exact-source bound. Independently reproduced all
roots, the R5 downgrade acceptance (pre-fix) and the R6 refusal (`DENY_REQUEST_POLICY_MISMATCH` at the
gateway), and confirmed the 3-file cone. `product_verdict PASS / governance_verdict PASS /
wave_verdict PASS`. No CONFIRMED_DEFECT.

## 6. Compiler (Gate 0)

`construction-acceptance-prompt-compiler` five stages PASS against contract
sha256 `82cb7049422a8f6d84c04d42a24cc56804c93944d43fe3e02a6800a1b43ef70a`; compiled thin-prompt bytes
retained (`R6_COMPILED_THIN_PROMPT.md`).

## 7. Claim ceiling / non-claims

This dossier claims **READY_FOR_W2_EXTERNAL_RECHALLENGE only**. NOT_EXTERNALLY_ACCEPTED, W3_NOT_STARTED,
NOT_MERGED, NOT_RELEASED, NOT_PRODUCTION, NO_WORLD_EFFECT.
