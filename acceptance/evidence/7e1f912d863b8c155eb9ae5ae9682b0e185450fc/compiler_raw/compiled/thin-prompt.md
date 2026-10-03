# EXECUTABLE THIN CONSTRUCTION & ACCEPTANCE PROMPT

## 0. Machine Header
task_id: SWOF-W1-REPAIR-R4-BINDING-ORDER-PROOF-001
contract_schema: CAPC-PROMPT-CONTRACT/1
compiler_state: PROMPT_COMPILE_PASS

## 1. Mission / ChangeSet
Mission: Smallest-legal W1 R4 repair: materialize the authoritative HGK RP002-EXECUTION-BINDING/2 binding and prove admission/permit precede the first source write on a monotonic append-only event stream.
Expected outcome: A new W1 candidate whose raw evidence proves BINDING < PERMIT <= WRITER_START < FIRST_WRITE on one monotonic HGK sequence.
ChangeSet: NARROW_REPAIR
Affected domains: capability-ledger, capability-schema, capability-tests, documentation

## 2. Authority / Files-first order
Read and hash the exact sources below in order. Use their owned controls directly; do not restate or replace them.
- 1 attachments/SWOF_W1_NARROW_REPAIR_R3_EXECUTOR_PROMPT_v1.md #0-9 role=NORMATIVE
- 2 C:\Projects\Agent_Workspace\HG-KSEOS\src\hg_kseos spine.py role=NORMATIVE
- 3 SWOF_HGK_ACA_RBWI/SWOF_HGK_ACA_RBWI.md #10.1-10.4 role=NORMATIVE
- 4 attachments/SWOF_W1_R2_EXTERNAL_CHALLENGE_REPORT.md #5 role=SUPPORT
Equal-rank conflict => quarantine, TT, and stop the affected work.

## 3. Intent / Non-goals / Claim ceiling
Expected experience: Routine repair executed autonomously; HITL only at real authority edges.
Constraints:
- start from clean baseline be036588bdf2d509c929aba9bc2bf0525674bb7a
- materialize a real RP002-EXECUTION-BINDING/2 before any source mutation
- ordering must use a monotonic append-only HGK stream, not wall-clock
- no force-push of PR #2 or PR #3
- do not reuse ed28b784 or 6b0e11e as the R4 subject
Non-goals:
- W2-W5 implementation
- architecture reset
- second control plane
- provider activation
Authorized mutations:
- SWOF after admission
- HG-KSEOS governed spine state
- GitHub shw097-team/SWOF branches and a new PR
Forbidden mutations:
- source corpus
- Fabric authoritative source
- HG-KSEOS source code
- remote merge
- release
- production
Claim ceiling: LOCAL

## 4. Active / Deferred / Forbidden scope
Active:
- HGK-EXECUTION-BINDING: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF-CAPABILITY-LEDGER: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
Non-active:
- none
Do not install, enable, or qualify a non-active capability.

## 5. Baseline / Reuse / Do-not-redo
Baseline: required=true; verified=true; reuse_prior_pass=true
Do not reopen:
- src/fabric
- src/knowledge
- src/admission
- src/profile
Verify source and candidate bindings before reuse. A tracked mutation invalidates the affected seal.

## 6. Implementation and qualification gates
Use Manifest → owner WP/RBWI → TaskSpec/WorkOrder → active AGENTS/SKILLS → Harness/Loop.
Runtime closure:
- HGK-EXECUTION-BINDING: verdict=RUNTIME_READY; work=none
- SWOF-CAPABILITY-LEDGER: verdict=RUNTIME_READY; work=none
Required user journeys:
- J-R3-ORDER: prove governance admission preceded the first source mutation → PRE_MUTATION_ADMISSION_RECEIPT frozen with real spine readback before any source byte changed
Acceptance predicates:
- ACC-R4-COMPILER subject=SWOF-W1-R3-DELIVERABLE depth=L1_SCHEMA_CONTRACT
- ACC-R4-BINDING-ORDER subject=HGK-EXECUTION-BINDING depth=L3_INTEGRATION_RUNTIME
- ACC-R3-LEDGER subject=SWOF-CAPABILITY-LEDGER depth=L2_UNIT_BEHAVIOR
- ACC-R4-JOURNEY subject=J-R3-ORDER depth=L3_INTEGRATION_RUNTIME
Proxy, static, maker, shared, file-presence, or summary evidence cannot close runtime behavior.

## 7. Failure / HITL / Repair / Resume
Use the smallest affected repair, focused tests, affected regression, independent recheck, and a new checkpoint.
Require HITL for: credentials, org authorization, destructive scope expansion, equal-rank conflict, break-glass, release or production.
No silent fallback. Use only a certified explicit substitute; otherwise return BLOCKED_EXTERNAL or BLOCKED_HITL.

## 8. Evidence / Independent acceptance / Candidate binding
Return case-specific raw receipts, command or probe, stdout/stderr/exit, producer, independent checker, source hashes, candidate head/package hash, invalidation, rollback, and residue readback.
Maker output is an evidence candidate, not a final verdict.

## 9. Termination / Final output
Terminal states: PASS, PARTIAL, FAIL, TEMP_CLOSED, PROMPT_COMPILE_BLOCKED, CHANGESET_RECOMPILE_REQUIRED.
Nonterminal pauses: HITL_AUTHORITY_EDGE.
Iteration or session pause requires a checkpoint and is not completion.
Return no claim above LOCAL.
