# R6 Fresh Independent Checker — Full Report

Checker status: fresh-context, independent, VERIFY_ONLY, read-only, NOT the maker.
No modifications, no commits to the candidate repo.
Subject: source `94e4c15e1040a159d0eb6ac3ef4089b421e60bf9` (branch wo/swof-w2-closure-r6).
Delegation: deleg_f3a757d7 (sa-0-4426308c), 24 api calls, 155.88s.

## product_verdict: PASS

1. **R5 defect reproduced** on `C:/tmp/swof-r5-check` @ 02736d3 (no request_resolver): CRITICAL/P5 request,
   caller-declared `required_authn_assurance="AAC2"`, AAC2 decision+token:
   `True APPROVE_BASIS_SATISFIED` => ACCEPTED (defect confirmed pre-fix).
2. **Same attack DENIED on R6** (trusted resolver returns canonical CRITICAL/AAC3, caller declares AAC2,
   AAC2 decision+token): `False DENY_REQUEST_POLICY_MISMATCH | required_authn_assurance`.
3. **Fail-closed paths** independently triggered:
   - absent request_resolver on gated path => `DENY_REQUEST_UNRESOLVED`
   - empty caller floor on CRITICAL => `DENY_AUTHN`
   - weak token AAC2 on trusted AAC3 floor => `DENY_AUTHN` (floor read from trusted request)
   - trusted required_authority=HA5 vs caller HA3 => `DENY_REQUEST_POLICY_MISMATCH`
   - gateway `assert_human_gate_satisfied` downgrade => `DENY_REQUEST_POLICY_MISMATCH` (no route bypass;
     only call site of verify_approval_token is rights.py:431)
4. **New deny codes** exist in APPROVAL_DENY_CODES and are surfaced as typed ApprovalDecision.code:
   `DENY_REQUEST_UNRESOLVED`, `DENY_REQUEST_POLICY_MISMATCH`.
5. **Regression re-run independently**: w2_security=421 OK; w1 16/21/25/17/12/22 all OK;
   w2 effect=116, assurance=144, observability=102 all OK. Grand total = 896 (113+783, >=883),
   zero-denominator roots = 0, all 10 roots exit 0. R6-vs-R5 security delta = +13 exactly.
   Focused `TestR6TrustedRequestBoundary` A1-A13: 13/13 OK.

Bypass analysis: resolver keyed on request_id + lineage exact-binding; any `_REQUEST_POLICY_FIELDS`
divergence => DENY_REQUEST_POLICY_MISMATCH; unknown request_id => DENY_REQUEST_UNRESOLVED. The verifier
never trusts caller-declared policy truth.

## governance_verdict: PASS
SoD maintained; evidence/source binding exact (`R6_FULL_REGRESSION_INDEX.json` source_sha = 94e4c15…;
raw log headers `git HEAD: 94e4c15e…`; compiler receipt source_sha_at_compile same). Index denominators
match re-derived root logs. Claim <= evidence.

## wave_verdict: PASS

## CONFIRMED_DEFECT
None in the R6 candidate.

## EVIDENCE_GAP (non-blocking) — RESOLVED
The checker observed `R6_POLICY_TRUST_ADJUDICATION.json` absent from the working R6_EVIDENCE dir at
check time. It is now present in the frozen immutable evidence commit
`6c58c21eee69391ba146e21e27b6d3b7f8f2211c` (verified via `git show 6c58c21:…/R6_POLICY_TRUST_ADJUDICATION.json`).
The check ran before the file was restored following a directory regeneration; the frozen subject is complete.

## NON_BLOCKING_OBSERVATIONS
- Seam trigger is `_required_authn_floor(request) is not None`; an absent caller floor skips the pinning
  and fails closed via DENY_AUTHN (no downgrade possible). Code-path distinction, not a security gap.
- The untracked `acceptance/` dir at worktree root is not part of the committed candidate tree.
