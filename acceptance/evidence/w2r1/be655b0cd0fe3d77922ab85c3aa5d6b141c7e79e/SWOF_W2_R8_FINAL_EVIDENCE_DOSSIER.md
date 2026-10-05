# SWOF W2 R8 — Final Evidence Dossier

```yaml
repair_id: SWOF-W2-R8-PI06-HUMANGATE-POLICY-SUBSTRATE
changeset: NARROW_REPAIR (PI06 minimum-policy conformance)
source_candidate_sha: be655b0cd0fe3d77922ab85c3aa5d6b141c7e79e
parent_source_sha: 335c231659f42badd15085e379fe252def988584
parent_evidence_sha: 36cc241bc5823ff0f489e4e4a7518a3d96653e97
claim_ceiling: READY_FOR_W2_R8_EXTERNAL_RECHALLENGE only
```

## 1. Finding closed — F-W2R7-EXT-001 (trusted request weaker than frozen PI06 minimum)

R6/R7 pinned the caller request to the TRUSTED request, but nothing proved the trusted request itself met
the frozen PI06 minimum. A trusted `release` request declaring P2/LOW/T2/AAC2/checker=false was accepted
(the verifier honored the trusted request's own weak floor); `required_coapprovals` was not representable;
the T3/checker floor was not canonically enforced.

Verified on the R7 subject `335c2316`: trusted release P2/LOW/T2/AAC2/checker=false -> the conformance
projection (absent in R7) now yields DENY_POLICY_FLOOR on R8 `be655b0c`.

## 2. Repair (smallest legal, ONE projection, no second engine)

- New `src/security/policy_projection.py`: ONE pure, source-derived PI06 minimum-policy projection.
  `minimum_policy(action, risk, permission)` and `policy_floor_errors(request)` with the concrete reasons.
  Reuses `rights.classify_operation` (one classifier, one enum source). Defines NO HA ordering — a PI06
  clause is a SET the request's authority composition must cover.
- `required_coapprovals: tuple[str, ...] = ()` added to `ApprovalRequest` (canonical set: tuple, unique,
  sorted, non-empty atoms) and to `_REQUEST_POLICY_FIELDS` (policy-owned pinning).
- Owner-injected `coapproval_resolver(request_id, required_authority_ref) -> HumanGateDecision | None` seam.
- The SAME `_policy_conformance_deny` is consumed by BOTH `rights.assert_human_gate_satisfied` (benign +
  gated paths, on the TRUSTED request) AND `humangate.verify_approval_token` (defense-in-depth).
- New deny codes: `DENY_POLICY_FLOOR`, `DENY_COAPPROVAL`, `DENY_T3_CHECKER`, `TEMP_CLOSED_POLICY_RESOLUTION`,
  `TEMP_CLOSED_AUTHORITY_RESOLUTION`.
- Fixtures repaired: the canonical-INVALID release fixture (LOW/P2/T2/AAC2/checker=false) replaced by a
  canonical-valid release fixture (P5/CRITICAL/T3/HA1+HA5/AAC3/checker=true) and a valid generic gated
  fixture.

Constraints honoured: no second policy engine; no global AAC3 force; no adapter fallback; RFC8785/JCS/
Ed25519/basis/nonce/generation/RUIN logic untouched. Files: 6 (+731/-62).

## 3. Adversarial focused set

`TestR8PolicyConformance` A01–A14 + P01–P04 (18 tests) all PASS: release+P2/LOW/T2/AAC2/checker-false =>
DENY_POLICY_FLOOR/DENY_T3_CHECKER; missing/stale/foreign/revoked coapproval => DENY_COAPPROVAL; caller
coapproval-set shrink => DENY_REQUEST_POLICY_MISMATCH; P4 secret missing {HA1,HA3} => floor/authority deny;
valid benign read / P3 external write / P5 release / tighter-domain preserved => PASS.

## 4. Regression

W1 = 113 ; W2 = 813 (security 451 = 433 R7 + 18 R8) ; grand_total = 926 (>=908, no shrink) ;
zero_denominator_roots = 0 ; all roots exit 0. R6/R7 retained tests green; R7 route sweep preserved.

## 5. Evidence (non-circular + byte-exact)

Child artifacts -> `R8_EVIDENCE_MANIFEST.json` (children only; not itself, not the pack) ->
`SWOF_W2_R8_EVIDENCE_RETURN_PACK.json` (hashes the manifest + selected children; no self/commit embedding)
-> immutable evidence commit E -> postpublication readset. Raw logs byte-bound (`newline=''`).

## 6. Non-claims

READY_FOR_W2_R8_EXTERNAL_RECHALLENGE only. NOT_EXTERNALLY_ACCEPTED, W3_NOT_STARTED, NOT_MERGED,
NOT_RELEASED, NOT_PRODUCTION, NO_WORLD_EFFECT.
