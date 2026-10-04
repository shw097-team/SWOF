# SWOF W2 — Closure R5 Final Evidence Dossier (Branch A, BLOCKER_CONFIRMED)

Order: `SWOF-CONSTRUCTION-002-W2-REPAIR-R5` · repair `SWOF-W2-CLOSURE-R5`
Repo: `shw097-team/SWOF` · branch `wo/swof-w2-closure-r1`
Producer: `hermes-orchestrator` · Independent checker: `fresh-context-VERIFY-ONLY`
ChangeSet: `NARROW_REPAIR` · Decision: **`BLOCKER_CONFIRMED` → Branch A (smallest repair applied)**

## 0. Equal-rank conflict — deterministic adjudication

Two same-rank external reports bound the R4 tuple and disagreed on `local_adapter`:

| | Report A | Report B |
|---|---|---|
| verdict | PASS_CHALLENGE | FAIL_CHALLENGE |
| local_adapter | NON_BLOCKING | CONFIRMED_DEFECT / S3 blocker |

**Adjudicated from frozen authority + exact R4 bytes (not by preference/count/chronology):** PI-PKG-06 DOC-03 requires CRITICAL→AAC3 (L526/689) and `required_authn_assurance` REQUIRED "meets floor / stale-weak deny" (L885); `adapter_kind` is not a canonical ApprovalRequirement field. On exact R4 subject `6f332c3c`, a full-route CRITICAL request carrying `adapter_kind="local_adapter"` and no canonical floor resolved to **AAC2** and passed verification (`APPROVE_BASIS_SATISFIED`), while the control (no adapter, same missing floor) correctly returned `DENY_AUTHN`. All six Gate 2D predicates held ⇒ **Report B confirmed; Report A's NON_BLOCKING fails on the trust axis.** Equal-rank conflict deterministically resolved.

Evidence: `R5_EXTERNAL_CONFLICT_ADJUDICATION.json` (raw probes + predicate rows).

## 1. Repair (smallest trust-boundary cone)

Single commit **`02736d3eeb6156e9763f202fbd63fff430e9eeb7`** — only 2 files:
- `src/security/humangate.py` — `_required_authn_floor()` no longer reads request-controlled `adapter_kind`; a canonical `ApprovalRequest` must carry its own valid `required_authn_assurance` (AAC1/2/3) or fails closed `None → DENY_AUTHN`. `approval_token`/`local_adapter` fallback removed; `adapter_kind` retained only as an inert marker the verifier never consults. No global AAC3 hard-code.
- `src/security/tests/test_humangate_currentness.py` — the seam test rewritten to assert the new fail-closed contract.

Gate 3 rule-d 6 honored: no cosmetic `trusted_adapter` rename; selectors rejected/deleted, not invented around.

## 2. Fresh independent checker (product + trust-boundary axis)

`R5_FRESH_CHECKER_RECEIPT.json` (`b0b78bfb485a07ff...`):
- R4 blocker **reproduced** on `6f332c3c` (floor AAC2, ok) then **closed** on `02736d3e` (floor None, DENY_AUTHN).
- Bypass attempts on new head: malformed/any-type `adapter_kind`, duck-object floor carry, missing/malformed/None/int/unicode/case-variant floor, extra field, subclass override ⇒ **all DENY_AUTHN / floor inert**. No adapter seam survives (verified statically + behaviorally).
- AAC lattice intact (AAC1+1 PASS; AAC2 floor+AAC1 token DENY; AAC3 floor+AAC2 DENY; CRITICAL missing floor DENY).
- `product_verdict=PASS, governance_verdict=PASS, wave_verdict=PASS, blocking_findings=[]`, `checker_ne_maker=true, checker_read_only=true`.
- Disclosed out-of-scope observation: DOC-03 CRITICAL→AAC3 is request-declared REQUIRED policy, not code-enforced (pre-existing R008 request-carries-floor design); a caller explicitly declaring AAC2 on CRITICAL is accepted. Not the adapter seam, not introduced by R5, not a counterexample to this repair.

## 3. Regression — no-shrink denominator

`R5_REGRESSION_RECEIPT.json` (`df0ea90d...`):
- W1 six roots = **113** (tests 16, fabric 21, knowledge 25, admission 17, profile 12, capability 22).
- W2 four roots = **770** (security 408, effect 116, assurance 144, observability 102).
- **Grand total 883 ≥ R4 minimum 883; no shrink; zero 0-denominator roots; all roots exit 0.**
- Note: `src/fabric/tests` discovery under `-s root -t .` raises an ImportError for `test_binding.py` (imports `tests.test_capability_contract`) — PRE-EXISTING import-path convention, unrelated to the security-only delta; both fabric files pass invoked directly (9+12=21).

## 4. HGK typed closure projection

`R5_W2_NORMATIVE_CLOSURE_PROJECTION.json` (`a777d6ba...`), typed APIs only, no direct SQL writes:
- R5 cone opened: `REQ-HGK-SWOF-W2R5-001` FROZEN, `WO-REQ-HGK-SWOF-W2R5-001` VERIFIED, `ACC-REQ-HGK-SWOF-W2R5-001` PASS (evidence_ref `EVD-W2R5-CHECKER`).
- Historical R2–R4 rows preserved (untouched).
- Final checkpoint **`CK-W2-AE96CED0`**: `source_digest` independently recomputed `5e829b205902ea584b40d2d9cb118bf3558f443b7533ccbe4797841082056d94` matches stored payload digest; `_checkpoint.evidence_refs` contains `SRC:02736d3e...` and `EVIDENCE_SHA:b0b78b...`.
- Denominator **8 / 8 / 8**, blocking open **0**, lifecycle points at final checkpoint.
- Post-projection fresh read-only verifier (`deleg_8105b6a1`) → **PASS** (closure genuinely bound; no over-claim).

## 5. Evidence return pack / next edge

`SWOF_W2_R5_EVIDENCE_RETURN_PACK.json` (`3c289d56...`) — all item hashes, producer/checker SoD, stale-`R5_APPLY_RECEIPT`/`R5_BASE` leftovers disclosed-excluded.

## 6. Exact SHA index (SHA-256, read back)

| artifact | path | sha256 |
|---|---|---|
| adjudication | `evidence/R5_EXTERNAL_CONFLICT_ADJUDICATION.json` | `73d9ef0269408887ea7e1789c3868de7ee049823bfa8378e917350d137f74052` |
| regression | `evidence/R5_REGRESSION_RECEIPT.json` | `df0ea90da1236ff9ff7d1460c5e3f17a9086b630b5ef30443664ef3c89037110` |
| checker receipt | `evidence/R5_FRESH_CHECKER_RECEIPT.json` | `b0b78bfb485a07ff7fc124602872cfeb3cad7f067d1554293f6de8bfdd9aa55a` |
| closure projection | `evidence/R5_W2_NORMATIVE_CLOSURE_PROJECTION.json` | `a777d6babfef6e2e1dd17b7f6eae59f5d936cbc8e9fe2c1c7ab4f2f125b85c57` |
| return pack | `evidence/SWOF_W2_R5_EVIDENCE_RETURN_PACK.json` | `3c289d56c556d56defbcf3785bf9acf12102e4310b3d94ada24220d428157968` |

## 7. Non-claims

`W1_EXACT_SUBJECT_PRESERVED` (7e1f912d/84ea30c2) · `W2_NOT_EXTERNALLY_ACCEPTED` (pending fresh external re-challenge) · `W3_NOT_STARTED` · `NOT_MERGED` · `NOT_RELEASED` · `NOT_PRODUCTION` · `NO_LIVE_WORLD_EFFECT`. No global AAC3 hard-code. Next authority edge: **read-only external re-challenge on exact dual-SHA subject** `02736d3e` (source) + new evidence commit (evidence SHA published in readset).