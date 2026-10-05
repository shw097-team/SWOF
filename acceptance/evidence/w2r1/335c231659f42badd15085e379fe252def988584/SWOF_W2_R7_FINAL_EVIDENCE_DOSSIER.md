# SWOF W2 R7 — Final Evidence Dossier

```yaml
repair_id: SWOF-W2-CLOSURE-R7
changeset: NARROW_REPAIR (trusted route-admission boundary)
source_candidate_sha: 335c231659f42badd15085e379fe252def988584
parent_source_sha: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
parent_evidence_sha: 6c58c21eee69391ba146e21e27b6d3b7f8f2211c
claim_ceiling: READY_FOR_W2_EXTERNAL_RECHALLENGE only
```

## 1. Finding closed — F-W2R6-EXT-001 (pre-verifier route suppression)

R6 pinned caller policy fields only INSIDE `verify_approval_token()`. The public enforcement seam
`assert_human_gate_satisfied` derived gate necessity from the caller request and returned at
`if not route.required` BEFORE the trusted resolver ran — a caller could lower every route-driving field
(operation/effect_risk_tier/permission_class/autonomy_tier) to a benign combination.

Deterministic cross-tree counterexample (trusted=release/CRITICAL/P5/T3/AAC3 vs caller=read/LOW/P2/T2/AAC1):
- R6 `94e4c15`: ACCEPT (bypass) — verifier/`request_resolver` never ran. Defect CONFIRMED.
- R7 `335c2316`: DENY_REQUEST_POLICY_MISMATCH. Closed.

## 2. Repair (smallest legal)

In `assert_human_gate_satisfied`, BEFORE the benign NONE return, when a request is supplied:
1. resolve the trusted current request via the existing owner-injected `request_resolver`
   (`_resolve_current_request`); absent resolver / missing ctx / stale / foreign => `DENY_REQUEST_UNRESOLVED`;
2. request_id parity: resolved request must carry the same canonical `request_id` (defense-in-depth parity
   with the R6 verifier path) else `DENY_REQUEST_UNRESOLVED`;
3. pin the caller request to the trusted request on `_REQUEST_POLICY_FIELDS`; divergence =>
   `DENY_REQUEST_POLICY_MISMATCH`;
4. derive RUIN precedence and the route from the TRUSTED request;
5. require the SUPPLIED route to equal the trusted-derived route on `required` + `route` + `authority_edge`,
   else `ROUTE_UNDERSTATES_ACTION`;
6. only then honour a trusted-derived benign NONE.

Gated path unchanged: typed token + `verify_approval_token`; R6 verifier-level `request_resolver` checks
RETAINED as defense-in-depth. No second policy engine, no global AAC3 force, no adapter fallback.
Files: `src/security/rights.py`, `src/security/tests/test_rights.py`,
`src/security/tests/test_humangate_currentness.py`.

## 3. Adversarial focused set

`TestR7TrustedRouteAdmission` A1–A9 + P1–P3 (12 tests) all PASS: trusted-consequential vs caller-benign
clone => DENY; operation-only / risk-only / permission-only / autonomy-only / combined suppression =>
DENY; fake NONE route + gated trusted => DENY; missing resolver => fail closed; stale/foreign => fail
closed; route authority_edge mismatch => DENY; exact benign => NONE/PASS; exact gated + valid token => PASS.

## 4. Regression

W1 = 113 ; W2 = 795 (security 433 = 421 R6 + 12 R7) ; grand_total = 908 (>=896, no shrink) ;
zero_denominator_roots = 0 ; all roots exit 0.

## 5. Retained invariants

R6 `TestR6TrustedRequestBoundary` (13/13); local_adapter missing-floor DENY; P3/P4/P5 floors;
RUIN/UNKNOWN_RUIN precedence; basis/JCS/Ed25519/currentness/generation/decision/authority/replay/T3 checker.

## 6. Evidence (non-circular + byte-exact)

- `R7_EVIDENCE_MANIFEST.json` hashes CHILD artifacts only; it does NOT hash itself and does NOT hash the
  Return Pack (fixes EG-W2R6-EXT-001 self/mutual-recursion).
- `SWOF_W2_R7_EVIDENCE_RETURN_PACK.json` hashes the manifest + selected children; it does NOT embed the
  evidence commit SHA that contains it (state `PREPUBLICATION`).
- Raw logs are written with `newline=""` so each manifest/index digest binds the LITERAL on-disk bytes
  (fixes the LF-vs-CRLF digest gap found in a prior check).
- The postpublication readset (support commit) records source SHA, evidence commit E, blob IDs, and
  recomputed SHA-256/bytes for the manifest and pack.

## 7. Non-claims

READY_FOR_W2_EXTERNAL_RECHALLENGE only. NOT_EXTERNALLY_ACCEPTED, W3_NOT_STARTED, NOT_MERGED,
NOT_RELEASED, NOT_PRODUCTION, NO_WORLD_EFFECT.
