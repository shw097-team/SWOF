# EXECUTABLE THIN CONSTRUCTION & ACCEPTANCE PROMPT

## 0. Machine Header
task_id: SWOF-W1-R4-EVIDENCE-ONLY-CLEANUP-W2-ENTRY-001
contract_schema: CAPC-PROMPT-CONTRACT/1
compiler_state: PROMPT_COMPILE_PASS

## 1. Mission / ChangeSet
Mission: Evidence-only acceptance cleanup of the frozen W1 R4 subject: complete the gate-calibration denominator, supersede the stale packaging receipt truthfully, reclassify linkage modes, adjudicate the historical compiler-provenance defect non-retroactively, and prepare the W2 entry carry-forward gate.
Expected outcome: A new immutable evidence commit bound to the unchanged source 7e1f912d, with the four R4 findings closed/adjudicated and a W2 handoff gate.
ChangeSet: EVIDENCE_ONLY
Affected domains: evidence, acceptance-packaging, gate-calibration, compiler-provenance

## 2. Authority / Files-first order
Read and hash the exact sources below in order. Use their owned controls directly; do not restate or replace them.
- 1 C:\Users\user\AppData\Local\hermes\attachments\SWOF_W1_R4_EVIDENCE_ONLY_CLEANUP_AND_W2_ENTRY_EXECUTOR_PROMPT_v1.md #0-9 role=NORMATIVE
- 2 C:\Users\user\AppData\Local\hermes\attachments\SWOF_W1_R4_EXTERNAL_CHALLENGE_AND_W2_ENTRY_DECISION.md #5 role=NORMATIVE
- 3 C:\Projects\Agent_Workspace\知識庫\實作相關DOC\Fabric vNext\Semantic World OS Fabric\SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages\SWOF_HGK_ACA_RBWI\SWOF_HGK_ACA_RBWI.md #10.1-10.4,21,22 role=NORMATIVE
- 4 C:\Projects\Agent_Workspace\知識庫\實作相關DOC\HG-KSEOS\construction-acceptance-prompt-compiler\construction-acceptance-prompt-compiler\construction-acceptance-prompt-compiler_SKILL.md C0-C9 role=NORMATIVE
- 5 C:\Projects\Agent_Workspace\HG-KSEOS\src\hg_kseos lifecycle.py,spine.py role=NORMATIVE
- 6 shw097-team/SWOF#4 branch repair/w1-r4-binding-order-proof @ 7e1f912d863b8c155eb9ae5ae9682b0e185450fc role=STATE_EVIDENCE
- 7 shw097-team/SWOF evidence/w1-r4-binding-order-proof @ 206ab073e92541cbb0d2acab8a3beebbcfe8c9e9 role=STATE_EVIDENCE
- 8 C:\Users\user\AppData\Local\hermes\attachments\SWOF_W1_NARROW_REPAIR_R4_EXECUTOR_PROMPT_v1.md historical-predecessor role=SUPPORT
- 9 C:\Users\user\AppData\Local\hermes\attachments\SWOF_W1_NARROW_REPAIR_R3_EXECUTOR_PROMPT_v1.md historical-predecessor role=SUPPORT
Equal-rank conflict => quarantine, TT, and stop the affected work.

## 3. Intent / Non-goals / Claim ceiling
Expected experience: Routine evidence cleanup executed autonomously; HITL only at real authority edges.
Constraints:
- frozen source 7e1f912d863b8c155eb9ae5ae9682b0e185450fc must not be modified
- no new W1 source candidate
- historical R4 evidence commit 206ab073e92541cbb0d2acab8a3beebbcfe8c9e9 treated read-only
- no force-push of PR #4
- no rewrite of historical compiler receipts
Non-goals:
- W1 source replay
- five-file reapply
- W2 product mutation
- provider activation
- merge/release/production
Authorized mutations:
- HG-KSEOS evidence workspace
- GitHub shw097-team/SWOF evidence branch (new commit only)
Forbidden mutations:
- SWOF product source
- source corpus
- Fabric authoritative source
- HG-KSEOS source code
- remote merge
- release
- production
Claim ceiling: LOCAL

## 4. Active / Deferred / Forbidden scope
Active:
- W1-R4-ACCEPTANCE-CLEANUP: ACTIVE_REQUIRED; action=QUALIFY; runtime_required=true
- W1-CARRY-FORWARD: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
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
- schemas
- README.md
Verify source and candidate bindings before reuse. A tracked mutation invalidates the affected seal.

## 6. Implementation and qualification gates
Use Manifest → owner WP/RBWI → TaskSpec/WorkOrder → active AGENTS/SKILLS → Harness/Loop.
Runtime closure:
- W1-R4-ACCEPTANCE-CLEANUP: verdict=RUNTIME_READY; work=none
- W1-CARRY-FORWARD: verdict=RUNTIME_READY; work=none
Required user journeys:
- J-EV-CLEANUP: clean up the R4 acceptance/provenance debt without changing the frozen W1 source → a new evidence commit bound to 7e1f912d closing four findings
- J-EV-W2-ENTRY: hand off to W2 preconstruction with honest carrying of the W1 acceptance debt → W1_CARRY_FORWARD_GATE with W2 preconstruction GO and mutation CONDITIONAL_GO
Acceptance predicates:
- ACC-EV-DELIVERABLE subject=SWOF-W1-R4-EVIDENCE-CLEANUP-DELIVERABLE depth=L2_UNIT_BEHAVIOR
- ACC-EV-JOURNEY-CLEANUP subject=J-EV-CLEANUP depth=L2_UNIT_BEHAVIOR
- ACC-EV-JOURNEY-W2 subject=J-EV-W2-ENTRY depth=L2_UNIT_BEHAVIOR
- ACC-EV-CALIBRATION subject=W1-R4-ACCEPTANCE-CLEANUP depth=L1_SCHEMA_CONTRACT
- ACC-EV-LINKAGE subject=W1-R4-LINKAGE depth=L1_SCHEMA_CONTRACT
- ACC-EV-PROVENANCE subject=W1-R4-COMPILER-PROVENANCE depth=L1_SCHEMA_CONTRACT
- ACC-EV-W2-ENTRY subject=W1-CARRY-FORWARD depth=L2_UNIT_BEHAVIOR
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
