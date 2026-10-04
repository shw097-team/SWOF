# SWOF W2 Closure Repair R4 - Final Evidence Dossier

```yaml
repair_id: SWOF-W2-CLOSURE-R4
order_id: SWOF-CONSTRUCTION-002-W2-REPAIR-001
final_source_candidate_sha: 6f332c3cedc52bafc98949f4ce9226b1d1696bc3
repair_base_sha: 0b8ecb0888fbd53b5698f603c90b580ac83dd69d
gate_set_passed: True
independent_wave_verdict: PASS
local_closure_receipt_sha256: 694fc2ac187a8e0df4ace2c783d188d12be9cdb71b30f1f88e308371e82844cb
```

## 1. Report conflict adjudication

- Base `0b8ecb08`: 9 adjudication rows; the frozen formula vs the shipped newline recipe DIFFER=True
- Both defects reproduced deterministically on the frozen bytes, so Branch B (product repair) was the only lawful route, not Branch A.
- After repair, the identical probe set returns CLOSED/CLOSED/CLOSED (A/B/C), with positive controls intact (18/18 post-repair probes hold).

## 2. Product source change

- Cumulative W2 surface (all repair rounds): `src/security/rights.py` (currentness fail-closed + credential expiry), `src/security/humangate.py` (typed exact-bound ApprovalToken with TOK-INV-001..014 first-fail codes), `src/security/__init__.py`, two JSON schemas and the security tests. No other subsystem was touched.
- THIS round (R4) ChangeSet: `src/security/humangate.py`, `src/security/tests/test_humangate_currentness.py`, `src/security/tests/test_rights.py` only. The wider surface above is inherited from earlier rounds and is not re-attributed to R4.

## 3. Test denominator

- W1 accepted regression: **113** (baseline 113 preserved)
- W2 roots: src/security/tests=408, src/effect/tests=116, src/assurance/tests=144, src/observability/tests=102
- Grand total: **883**, zero-denominator roots: none

## 4. Corrected closure reducer

- `reduce_gate_w2_6()` required wave/governance PASS, checker != maker, read-only, subject match.
- Reducer fixtures: **9/9** hold (includes 'product PASS + checker PARTIAL => FAIL').
- The claim string is now emitted only by `claim_for()` from the actual checker verdict.

## 5. Independent checker

- Identity: `fresh-5th-checker-swof-w2r4-r008-6f332c3` (fresh context, VERIFY_ONLY, read-only)
- Product lane: `PASS` / governance lane: `PASS` / overall-wave: **`PASS`**

## 6. Canonical HGK closure leg

- Resolved: `True` (checkpoint `CK-W2-C72F516B`)
- The typed HGK API CAN move `acceptances.verdict` off `NOT_RUN`: `SharedSpine.resolve_acceptance(...)` is materialised, so the W2 denominator is closable through typed APIs with no direct SQL.
- Raw binding evidence: `exact_source_binding` in the projection exposes the stored payload plus a recompute recipe so an external reviewer can recompute `source_digest`.

## 7. Non-claims

- `NOT_EXTERNALLY_ACCEPTED`, `W3_NOT_STARTED`, `NO_MERGE`, `NO_RELEASE`, `NO_PRODUCTION`, `NO_WORLD_EFFECT_ACCEPTANCE`
