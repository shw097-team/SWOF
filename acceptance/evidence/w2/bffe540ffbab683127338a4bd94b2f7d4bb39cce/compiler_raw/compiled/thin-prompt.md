# EXECUTABLE THIN CONSTRUCTION & ACCEPTANCE PROMPT

## 0. Machine Header
task_id: SWOF-CONSTRUCTION-002-W2-SECURITY-EFFECT-ASSURANCE-001
contract_schema: CAPC-PROMPT-CONTRACT/1
compiler_state: PROMPT_COMPILE_PASS

## 1. Mission / ChangeSet
Mission: Implement and independently close W2 - the Security/Effect/Assurance substrate - on top of the externally accepted W1 source commit, then publish a W2 source candidate and a separate sanitized evidence subject.
Expected outcome: SWOF-owned, executable, fail-closed security, effect and assurance contracts with adversarial coverage, an independent checker receipt and a subject-bound evidence envelope READY_FOR_W2_EXTERNAL_ACCEPTANCE.
ChangeSet: CONTINUATION
Affected domains: security, effect, assurance, observability, schemas, documentation

## 2. Authority / Files-first order
Read and hash the exact sources below in order. Use their owned controls directly; do not restate or replace them.
- 1 attachments/SWOF_W2_Executor_Thin_Prompt_v1.md attachments/SWOF_W2_Executor_Thin_Prompt_v1.md role=NORMATIVE
- 2 C:\Projects\Agent_Workspace\HG-KSEOS\src\hg_kseos spine.py role=NORMATIVE
- 3 SWOF_HGK_ACA_RBWI/SWOF_HGK_ACA_RBWI.md #10.1-10.4 role=NORMATIVE
- 4 attachments/SWOF_W1_R4_EVIDENCE_ONLY_FINAL_CLOSURE_EXTERNAL_CHALLENGE_REPORT.md #0,#12 role=SUPPORT
- 3 SWOF_HGK_ACA_RBWI/SWOF_HGK_ACA_RBWI.md #10.3-10.4,#21.1-21.5 role=NORMATIVE
Equal-rank conflict => quarantine, TT, and stop the affected work.

## 3. Intent / Non-goals / Claim ceiling
Expected experience: Routine W2 bounded repairs run autonomously; HITL only at real authority edges (credentials, destructive scope expansion, release/production).
Constraints:
- start from the accepted W1 source 7e1f912d863b8c155eb9ae5ae9682b0e185450fc
- no W1 source/evidence repair; the accepted tuple is immutable input
- no merge of PR #4 or any W2 PR; no release; no production; no live world effect
- no mutation of the source corpus, HG-KSEOS or Fabric canonical roots
- no provider/tool activation merely because it is named
- one canonical writer; checker never repairs the candidate
Non-goals:
- W3-W5 implementation
- second control plane
- second semantic root
- second compiler
- provider activation
- live effect
Authorized mutations:
- SWOF/ under the admitted W2 WorkOrders
- HG-KSEOS governed spine state and W2 evidence root
- local W2 candidate/evidence branches
Forbidden mutations:
- source corpus
- Fabric canonical contracts
- HG-KSEOS source code
- remote merge
- release
- production
- live world effect
Claim ceiling: LOCAL

## 4. Active / Deferred / Forbidden scope
Active:
- HGK-EXECUTION-BINDING: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF-SECURITY-SUBSTRATE: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF-EFFECT-SUBSTRATE: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF-ASSURANCE-SUBSTRATE: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF-OBSERVABILITY-HOOKS: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
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
- src/capability
Verify source and candidate bindings before reuse. A tracked mutation invalidates the affected seal.

## 6. Implementation and qualification gates
Use Manifest → owner WP/RBWI → TaskSpec/WorkOrder → active AGENTS/SKILLS → Harness/Loop.
Runtime closure:
- HGK-EXECUTION-BINDING: verdict=RUNTIME_READY; work=none
- SWOF-SECURITY-SUBSTRATE: verdict=RUNTIME_READY; work=none
- SWOF-EFFECT-SUBSTRATE: verdict=RUNTIME_READY; work=none
- SWOF-ASSURANCE-SUBSTRATE: verdict=RUNTIME_READY; work=none
- SWOF-OBSERVABILITY-HOOKS: verdict=RUNTIME_READY; work=none
Required user journeys:
- J-W2-SUBSTRATE: a security/effect/assurance substrate that fails closed and whose evidence cannot be forged, reused or self-certified → independent W2 checker receipt + subject-bound evidence envelope
Acceptance predicates:
- ACC-W2-COMPILER subject=SWOF-W2-DELIVERABLE depth=L1_SCHEMA_CONTRACT
- ACC-W2-SECURITY subject=SWOF-SECURITY-SUBSTRATE depth=L3_INTEGRATION_RUNTIME
- ACC-W2-EFFECT subject=SWOF-EFFECT-SUBSTRATE depth=L3_INTEGRATION_RUNTIME
- ACC-W2-ASSURANCE subject=SWOF-ASSURANCE-SUBSTRATE depth=L3_INTEGRATION_RUNTIME
- ACC-W2-OPSHOOKS subject=SWOF-OBSERVABILITY-HOOKS depth=L2_UNIT_BEHAVIOR
- ACC-W2-BINDING-ORDER subject=HGK-EXECUTION-BINDING depth=L3_INTEGRATION_RUNTIME
- ACC-W2-REG-RUN subject=SWOF-W1-DEPENDENCY-CONE depth=L3_INTEGRATION_RUNTIME
- ACC-W2-REQ subject=W2-SECURITY-EFFECT-ASSURANCE depth=L3_INTEGRATION_RUNTIME
- ACC-W2-JOURNEY subject=J-W2-SUBSTRATE depth=L3_INTEGRATION_RUNTIME
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
