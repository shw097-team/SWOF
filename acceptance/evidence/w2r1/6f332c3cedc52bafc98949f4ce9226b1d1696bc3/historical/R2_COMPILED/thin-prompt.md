# EXECUTABLE THIN CONSTRUCTION & ACCEPTANCE PROMPT

## 0. Machine Header
task_id: SWOF-W2-CLOSURE-R2
contract_schema: CAPC-PROMPT-CONTRACT/1
compiler_state: PROMPT_COMPILE_PASS

## 1. Mission / ChangeSet
Mission: Execute ONE bounded W2 closure repair (R2) against exact baseline 7a0b4acbe14daca2061ba9b927013adf8aaf48b5: unify the HumanGate trigger onto the canonical risk/permission classification, add RUIN/UNKNOWN_RUIN precedence, make the ApprovalToken basis/lineage/integrity canonical, bind the final HGK checkpoint to the exact new source, make the denominator non-vacuous, regenerate the evidence/readset, and republish for external re-challenge.
Expected outcome: A new exact source candidate plus a separate sanitized evidence commit, locally closed and independently verified, packaged for read-only external re-challenge.
ChangeSet: NARROW_REPAIR
Affected domains: security, HumanGate, rights, evidence-transport, normative-closure

## 2. Authority / Files-first order
Read and hash the exact sources below in order. Use their owned controls directly; do not restate or replace them.
- R1 attachments/SWOF_W2_Closure_R2_Executor_Thin_Prompt_v1.md attachments/SWOF_W2_Closure_R2_Executor_Thin_Prompt_v1.md role=NORMATIVE
- R3 C:\Projects\Agent_Workspace\知識庫\實作相關DOC\Fabric vNext\Semantic World OS Fabric\SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages\PI-PKG\DOC\PI-PKG-06_DOC C:\Projects\Agent_Workspace\知識庫\實作相關DOC\Fabric vNext\Semantic World OS Fabric\SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages\PI-PKG\DOC\PI-PKG-06_DOC role=NORMATIVE
- R5 C:\Projects\Agent_Workspace\知識庫\實作相關DOC\Fabric vNext\Semantic World OS Fabric\SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages\SWOF_HGK_ACA_RBWI\SWOF_HGK_ACA_RBWI.md C:\Projects\Agent_Workspace\知識庫\實作相關DOC\Fabric vNext\Semantic World OS Fabric\SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages\SWOF_HGK_ACA_RBWI\SWOF_HGK_ACA_RBWI.md role=NORMATIVE
- R6 C:\Projects\Agent_Workspace\HG-KSEOS src/hg_kseos role=NORMATIVE
- R7 C:\Projects\Agent_Workspace\HG-KSEOS\var\shared-spine\hg-kseos.db var/shared-spine/hg-kseos.db role=STATE_EVIDENCE
- R8 attachments/*EXTERNAL_CHALLENGE_REPORT* external challenge findings role=SUPPORT
Equal-rank conflict => quarantine, TT, and stop the affected work.

## 3. Intent / Non-goals / Claim ceiling
Expected experience: The user supplies only the order and the challenge reports; bounded repair, verification, closure and packaging proceed without repeated HITL.
Constraints:
- Files-first; canonical PI06/RBWI outrank candidate tests and prior receipts
- No second HumanGate/router/authority subsystem; repair the existing seam
- No direct consumer SQL into HGK canonical state; typed APIs only
- No approximated JCS presented as RFC 8785; no shape-only test presented as Ed25519
- No token may override RUIN/UNKNOWN_RUIN; no vacuous 0/0 closure denominator
- No W3 dispatch, no merge, no release, no production, no live/world effect
Non-goals:
- broad W2 refactor
- reopening closed W1/W2 work without new counterevidence
- rollback of SharedSpine.resolve_acceptance
- hand-editing superseded receipts
- a second RBWI/reducer/workflow engine
Authorized mutations:
- src/security/humangate.py
- src/security/rights.py
- schemas/security/approval_token.schema.json
- src/security/tests/test_humangate_currentness.py
- src/security/tests/test_rights.py
- var/swof-construction-002-w2-repair-001/**
Forbidden mutations:
- W1 accepted subject
- HGK shared core beyond the retained ChangeSet
- Fabric canonical contracts
- main branch
- release/production surfaces
Claim ceiling: LOCAL

## 4. Active / Deferred / Forbidden scope
Active:
- SWOF_HUMANGATE_RISK_TRIGGER: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF_HUMANGATE_RUIN_PRECEDENCE: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF_APPROVALTOKEN_CANONICAL_INTEGRITY: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- HGK_EXACT_SUBJECT_CLOSURE: ACTIVE_SELECTED; action=USE_NATIVE; runtime_required=true
- SWOF_EVIDENCE_TRANSPORT: ACTIVE_SELECTED; action=USE_NATIVE; runtime_required=true
Non-active:
- none
Do not install, enable, or qualify a non-active capability.

## 5. Baseline / Reuse / Do-not-redo
Baseline: required=true; verified=true; reuse_prior_pass=true
Do not reopen:
- W1 implementation
- effect substrate outside the HumanGate claim path
- assurance substrate
- observability substrate
- provider/admission/knowledge/profile surfaces
- release/production
Verify source and candidate bindings before reuse. A tracked mutation invalidates the affected seal.

## 6. Implementation and qualification gates
Use Manifest → owner WP/RBWI → TaskSpec/WorkOrder → active AGENTS/SKILLS → Harness/Loop.
Runtime closure:
- SWOF_HUMANGATE_RISK_TRIGGER: verdict=RUNTIME_READY; work=none
- SWOF_HUMANGATE_RUIN_PRECEDENCE: verdict=RUNTIME_READY; work=none
- SWOF_APPROVALTOKEN_CANONICAL_INTEGRITY: verdict=RUNTIME_READY; work=none
- HGK_EXACT_SUBJECT_CLOSURE: verdict=RUNTIME_READY; work=none
- SWOF_EVIDENCE_TRANSPORT: verdict=RUNTIME_READY; work=none
Required user journeys:
- UJ-R2-P3-GATE: a caller whose request is classified P3 cannot act without exact Human authority → DENY_P3_TOKEN_REQUIRED
- UJ-R2-RUIN: a ruin-class action is vetoed even when a fully valid token is presented → HARD_VETO_RUIN / SAFE_STOP_UNKNOWN_RUIN
- UJ-R2-EVIDENCE: the handed-off evidence subject is internally consistent and exactly bound → descriptor hashes recomputed from committed bytes
Acceptance predicates:
- ACC-SWOF_HUMANGATE_RISK_TRIGGER subject=SWOF_HUMANGATE_RISK_TRIGGER depth=L3_INTEGRATION_RUNTIME
- ACC-SWOF_HUMANGATE_RUIN_PRECEDENCE subject=SWOF_HUMANGATE_RUIN_PRECEDENCE depth=L3_INTEGRATION_RUNTIME
- ACC-SWOF_APPROVALTOKEN_CANONICAL_INTEGRITY subject=SWOF_APPROVALTOKEN_CANONICAL_INTEGRITY depth=L3_INTEGRATION_RUNTIME
- ACC-HGK_EXACT_SUBJECT_CLOSURE subject=HGK_EXACT_SUBJECT_CLOSURE depth=L3_INTEGRATION_RUNTIME
- ACC-SWOF_EVIDENCE_TRANSPORT subject=SWOF_EVIDENCE_TRANSPORT depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R2-001 subject=REQ-HGK-SWOF-W2R2-001 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R2-002 subject=REQ-HGK-SWOF-W2R2-002 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R2-003 subject=REQ-HGK-SWOF-W2R2-003 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R2-004 subject=REQ-HGK-SWOF-W2R2-004 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R2-005 subject=REQ-HGK-SWOF-W2R2-005 depth=L3_INTEGRATION_RUNTIME
- ACC-DEL-CODE subject=DEL-CODE depth=L3_INTEGRATION_RUNTIME
- ACC-DEL-EVIDENCE subject=DEL-EVIDENCE depth=L3_INTEGRATION_RUNTIME
- ACC-DEL-REPORT subject=DEL-REPORT depth=L3_INTEGRATION_RUNTIME
- ACC-UJ-R2-P3-GATE subject=UJ-R2-P3-GATE depth=L3_INTEGRATION_RUNTIME
- ACC-UJ-R2-RUIN subject=UJ-R2-RUIN depth=L3_INTEGRATION_RUNTIME
- ACC-UJ-R2-EVIDENCE subject=UJ-R2-EVIDENCE depth=L3_INTEGRATION_RUNTIME
Proxy, static, maker, shared, file-presence, or summary evidence cannot close runtime behavior.

## 7. Failure / HITL / Repair / Resume
Use the smallest affected repair, focused tests, affected regression, independent recheck, and a new checkpoint.
Require HITL for: equal-rank source conflict, credential or permission grant, repository visibility policy, mutation outside authorized roots, destructive scope expansion, live consequential effects, merge/release/production.
No silent fallback. Use only a certified explicit substitute; otherwise return BLOCKED_EXTERNAL or BLOCKED_HITL.

## 8. Evidence / Independent acceptance / Candidate binding
Return case-specific raw receipts, command or probe, stdout/stderr/exit, producer, independent checker, source hashes, candidate head/package hash, invalidation, rollback, and residue readback.
Maker output is an evidence candidate, not a final verdict.

## 9. Termination / Final output
Terminal states: PASS, PARTIAL, FAIL, TEMP_CLOSED.
Nonterminal pauses: TEMP_CLOSED_SOURCE, TEMP_CLOSED_RUNTIME, TEMP_CLOSED_STATE, TEMP_CLOSED_EVIDENCE, TEMP_CLOSED_GITHUB, PROMPT_COMPILE_BLOCKED, FAIL_SECURITY.
Iteration or session pause requires a checkpoint and is not completion.
Return no claim above LOCAL.
