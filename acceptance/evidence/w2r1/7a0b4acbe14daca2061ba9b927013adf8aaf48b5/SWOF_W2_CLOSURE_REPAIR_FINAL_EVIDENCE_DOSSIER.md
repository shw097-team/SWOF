# SWOF W2 Closure Repair R1 - Final Evidence Dossier

```yaml
repair_id: SWOF-W2-CLOSURE-R1
order_id: SWOF-CONSTRUCTION-002-W2-REPAIR-001
final_source_candidate_sha: 7a0b4acbe14daca2061ba9b927013adf8aaf48b5
repair_base_sha: bffe540ffbab683127338a4bd94b2f7d4bb39cce
gate_set_passed: True
independent_wave_verdict: PASS
local_closure_receipt_sha256: c7c479574cef8fc9a622e99189a1ed89b12fea2ffc82ec868826e8c710039d3b
```

## 1. Report conflict adjudication

- Base `bffe540f` R-C1: `PRODUCT_DEFECT_CONFIRMED:F-W2-EXT-001`; R-C2: `PRODUCT_DEFECT_CONFIRMED:F-W2-EXT-002`
- Both defects reproduced deterministically on the frozen bytes, so Branch B (product repair) was the only lawful route, not Branch A.
- After repair, the identical probe set returns R-C1 `PRODUCT_DEFECT_NOT_REPRODUCED` and R-C2 `PRODUCT_DEFECT_NOT_REPRODUCED`, with positive controls intact (14/14 post-repair probes hold).

## 2. Product source change

Changed, because the defects were real: `src/security/rights.py` (currentness fail-closed + credential expiry), new `src/security/humangate.py` (typed exact-bound ApprovalToken with TOK-INV-001..014 first-fail codes), `src/security/__init__.py`, two JSON schemas and the security tests. No other subsystem was touched.

## 3. Test denominator

- W1 accepted regression: **113** (baseline 113 preserved)
- W2 roots: src/security/tests=260, src/effect/tests=116, src/assurance/tests=144, src/observability/tests=102
- Grand total: **735**, zero-denominator roots: none

## 4. Corrected closure reducer

- `reduce_gate_w2_6()` required wave/governance PASS, checker != maker, read-only, subject match.
- Reducer fixtures: **9/9** hold (includes 'product PASS + checker PARTIAL => FAIL').
- The claim string is now emitted only by `claim_for()` from the actual checker verdict.

## 5. Independent checker

- Identity: `hermes-subagent-fresh-context-swof-w2-r3-final-verify` (fresh context, VERIFY_ONLY, read-only)
- Product lane: `PASS` / governance lane: `PASS` / overall-wave: **`PASS`**

## 6. Canonical HGK closure leg

- Verdict: `TYPED_API_CANNOT_RESOLVE_ACCEPTANCE_VERDICT` -> **TEMP_CLOSED_STATE**
- The typed HGK API contains no statement that can move `acceptances.verdict` off `NOT_RUN`, and `denominator()` treats that as an open edge, so the W2 denominator is structurally unclosable without direct SQL, which this order forbids.
- Close condition: a separate engineering-base ChangeSet adding `SharedSpine.resolve_acceptance(...)` (HITL: it mutates shared HGK core).

## 7. Non-claims

- `NOT_EXTERNALLY_ACCEPTED`, `W3_NOT_STARTED`, `NO_MERGE`, `NO_RELEASE`, `NO_PRODUCTION`, `NO_WORLD_EFFECT_ACCEPTANCE`
- The canonical final normative checkpoint is NOT bound; this is disclosed, not hidden.

