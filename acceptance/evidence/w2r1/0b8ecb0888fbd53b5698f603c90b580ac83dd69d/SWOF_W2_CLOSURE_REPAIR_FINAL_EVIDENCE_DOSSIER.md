# SWOF W2 Closure Repair R3 - Final Evidence Dossier

```yaml
repair_id: SWOF-W2-CLOSURE-R3
order_id: SWOF-CONSTRUCTION-002-W2-REPAIR-001
final_source_candidate_sha: 0b8ecb0888fbd53b5698f603c90b580ac83dd69d
repair_base_sha: b8e62b96463273e3475ff52a7a4a87831816927a
gate_set_passed: True
independent_wave_verdict: PASS
local_closure_receipt_sha256: 1f9a2c0f8dec6f99674431ec36a52ba8b7d4db1114c4573ebedbeee7777a903d
```

## 1. Report conflict adjudication

- Base `b8e62b96`: 9 adjudication rows; the frozen formula vs the shipped newline recipe DIFFER=True
- Both defects reproduced deterministically on the frozen bytes, so Branch B (product repair) was the only lawful route, not Branch A.
- After repair, the identical probe set returns CLOSED/CLOSED/CLOSED (A/B/C), with positive controls intact (17/17 post-repair probes hold).

## 2. Product source change

Changed, because the defects were real: `src/security/rights.py` (currentness fail-closed + credential expiry), new `src/security/humangate.py` (typed exact-bound ApprovalToken with TOK-INV-001..014 first-fail codes), `src/security/__init__.py`, two JSON schemas and the security tests. No other subsystem was touched.

## 3. Test denominator

- W1 accepted regression: **113** (baseline 113 preserved)
- W2 roots: src/security/tests=382, src/effect/tests=116, src/assurance/tests=144, src/observability/tests=102
- Grand total: **857**, zero-denominator roots: none

## 4. Corrected closure reducer

- `reduce_gate_w2_6()` required wave/governance PASS, checker != maker, read-only, subject match.
- Reducer fixtures: **9/9** hold (includes 'product PASS + checker PARTIAL => FAIL').
- The claim string is now emitted only by `claim_for()` from the actual checker verdict.

## 5. Independent checker

- Identity: `fresh-verify-w2r3-check4-0b8ecb0` (fresh context, VERIFY_ONLY, read-only)
- Product lane: `PASS` / governance lane: `PASS` / overall-wave: **`PASS`**

## 6. Canonical HGK closure leg

- Resolved: `True` (checkpoint `CK-W2-ADA77206`)
- The typed HGK API contains no statement that can move `acceptances.verdict` off `NOT_RUN`, and `denominator()` treats that as an open edge, so the W2 denominator is structurally unclosable without direct SQL, which this order forbids.
- Close condition: a separate engineering-base ChangeSet adding `SharedSpine.resolve_acceptance(...)` (HITL: it mutates shared HGK core).

## 7. Non-claims

- `NOT_EXTERNALLY_ACCEPTED`, `W3_NOT_STARTED`, `NO_MERGE`, `NO_RELEASE`, `NO_PRODUCTION`, `NO_WORLD_EFFECT_ACCEPTANCE`
- The canonical final normative checkpoint is NOT bound; this is disclosed, not hidden.

