# EXECUTABLE THIN CONSTRUCTION & ACCEPTANCE PROMPT

## 0. Machine Header
task_id: SWOF-W2-CLOSURE-R8
contract_schema: CAPC-PROMPT-CONTRACT/1
compiler_state: PROMPT_COMPILE_PASS

## 1. Mission / ChangeSet
Mission: Execute ONE bounded W2 closure repair (R8) that deterministically adjudicates the equal-rank R5 external-conflict on whether the current W2 public HumanGate/ApprovalRequest trust boundary still permits a caller to lower policy-owned security requirements (Report A F-W2R5-EXT-001 BLOCKER_CONFIRMED), then apply the smallest repair that makes caller-supplied policy/classification fields non-authoritative: add ONE owner-injected trusted current ApprovalRequest resolver so the verifier validates decision/token against canonical request truth (rejecting any caller downgrade/mismatch, fail-closed on missing/stale/foreign), rerun focused adversarial + full regression (W1>=113, grand>=883, zero shrink), fresh independent checker attacks the trust axis, HGK exact-source reclosure with new checkpoint, publish distinct exact evidence commit (raw logs, checker transcript, immutable Return Pack with no placeholders, exact compiler receipt + thin-prompt bytes), and stop at READY_FOR_W2_EXTERNAL_RECHALLENGE — never self-issue PASS_CHALLENGE and never dispatch W3.
Expected outcome: F-W2R5-EXT-001 (caller-controlled canonical policy floor) closed: CRITICAL/P4/P5 with caller weaker floor is DENIED; legitimate AAC1/2/3 floors preserved (no global AAC3 force); new exact R8 source + evidence committed, independently verified, packaged for read-only external re-challenge.
ChangeSet: NARROW_REPAIR
Affected domains: security, HumanGate, policy-owner-trust-boundary, evidence-transport, normative-closure

## 2. Authority / Files-first order
Read and hash the exact sources below in order. Use their owned controls directly; do not restate or replace them.
- R1 attachments/SWOF_W2_R8_Adjudication_Repair_Executor_Thin_Prompt_v1.md attachments/SWOF_W2_R8_Adjudication_Repair_Executor_Thin_Prompt_v1.md role=NORMATIVE
- R3 C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/PI-PKG/DOC/PI-PKG-06_DOC C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/PI-PKG/DOC/PI-PKG-06_DOC role=NORMATIVE
- R5 C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages role=NORMATIVE
- R8 src/hg_kseos src/hg_kseos role=NORMATIVE
- R8 var/shared-spine/hg-kseos.db var/shared-spine/hg-kseos.db role=STATE_EVIDENCE
- R2 attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REACCEPTANCE_REPORT_2026-10-04.md attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REACCEPTANCE_REPORT_2026-10-04.md role=NORMATIVE
- R2 attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REPORT_2026-10-04.md attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REPORT_2026-10-04.md role=NORMATIVE
Equal-rank conflict => quarantine, TT, and stop the affected work.

## 3. Intent / Non-goals / Claim ceiling
Expected experience: User supplies the R8 order and both R5 challenge reports; adjudication, minimal repair, verification, closure and packaging proceed without repeated HITL (HITL reserved for genuine authority edges).
Constraints:
- R8 is a NARROW trust-boundary repair: caller-supplied policy/classification fields must not become authoritative policy truth merely because ApprovalRequest is a canonical dataclass
- Add ONE owner-injected read-only trusted current request resolver/context analogous to decision_resolver and authority_policy seams (no second HumanGatePolicy engine)
- Fail closed on missing resolver, absent/stale/foreign request, or any caller policy-field downgrade/mismatch
- Minimum trust-bound comparison set only where frozen PI06/current model supports it: operation/operation_class, effect_risk_tier, permission_class, autonomy_tier, required_authority, required_authn_assurance, rollback_ref, independent_checker_required, request_id/decision_id lineage
- No global AAC3 force; no restore of adapter_kind fallback; no second policy engine; direct SQL into HGK forbidden
- No token overrides RUIN/UNKNOWN_RUIN; closure denominator non-vacuous; no self-issued external PASS; no W3 dispatch
- Evidence closure mandatory (Branch B is not chosen): raw focused probes, security+full regression logs, fresh checker transcript, immutable Return Pack with real hashes (no placeholders), exact compiled thin-prompt bytes
Non-goals:
- Reopening W1 or R5 accepted local_adapter closure
- Redesigning HumanGate or creating a second policy engine
- Hard-coding global AAC3
- Implementing W3 product/domain journeys, coapproval, action-class, persistent-nonce before affected W3 journey activates them
- Performing broad security hardening without a first-failing invariant
- Pre-implementing W4/W5
- Merging PR#7; releasing; deploying; production promotion; live/world effects
- Self-issuing external PASS_CHALLENGE
Authorized mutations:
- src/security/humangate.py
- src/security/rights.py
- src/security/__init__.py
- src/security/tests/test_humangate_currentness.py
- var/swof-construction-002-w2-repair-001/**
Forbidden mutations:
- W1 accepted subject
- R5 closed subject (02736d3eeb6156e9763f202fbd63fff430e9eeb7 if Branch B, but Branch A changes it)
- HGK shared core beyond retained ChangeSet
- Fabric canonical contracts
- main branch
- release/production surfaces
- W3 dispatch
Claim ceiling: LOCAL

## 4. Active / Deferred / Forbidden scope
Active:
- SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- HGK_EXACT_SUBJECT_CLOSURE_R8: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
- SWOF_EVIDENCE_TRANSPORT_R8: ACTIVE_REQUIRED; action=DESIGN; runtime_required=true
Non-active:
- none
Do not install, enable, or qualify a non-active capability.

## 5. Baseline / Reuse / Do-not-redo
Baseline: required=true; verified=true; reuse_prior_pass=false
Do not reopen:
- W1 implementation
- R5 local_adapter closure
- effect/assurance/observability outside cone
- provider/admission/knowledge/profile
- release/production
- W3 dispatch
Verify source and candidate bindings before reuse. A tracked mutation invalidates the affected seal.

## 6. Implementation and qualification gates
Use Manifest → owner WP/RBWI → TaskSpec/WorkOrder → active AGENTS/SKILLS → Harness/Loop.
Runtime closure:
- SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY: verdict=RUNTIME_READY; work=none
- SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING: verdict=RUNTIME_READY; work=none
- HGK_EXACT_SUBJECT_CLOSURE_R8: verdict=RUNTIME_READY; work=none
- SWOF_EVIDENCE_TRANSPORT_R8: verdict=RUNTIME_READY; work=none
Required user journeys:
- UJ-R8-TRUSTED-POLICY-BOUNDARY: A caller must never be able to lower a frozen policy-owned ApprovalRequirement (e.g. CRITICAL/P4/P5 AAC3) by constructing another ApprovalRequest with the same lineage but weaker required_authn_assurance/risk/permission/authority → verifier resolves a trusted current request and DENIES any caller policy-field downgrade/mismatch; missing/stale/foreign resolver fails closed
- UJ-R8-RETAINED: R5-closed request-floor and retained security invariants stay intact → AAC1/2/3 lattice, CRITICAL/AAC3, §15.5 basis, signed sets, P3/RUIN, unknown-op fail-closed preserved
- UJ-R8-EVIDENCE: Exact R8 dual-SHA evidence handoff for read-only external re-challenge with raw logs/checker transcript and immutable Return Pack → source candidate != evidence commit; raw focused probes/regression logs/checker transcript present; immutable Return Pack with real hashes; compiler receipt + exact Compiled Thin Prompt bytes
Acceptance predicates:
- ACC-SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY subject=SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY depth=L3_INTEGRATION_RUNTIME
- ACC-SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING subject=SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING depth=L3_INTEGRATION_RUNTIME
- ACC-HGK_EXACT_SUBJECT_CLOSURE_R8 subject=HGK_EXACT_SUBJECT_CLOSURE_R8 depth=L3_INTEGRATION_RUNTIME
- ACC-SWOF_EVIDENCE_TRANSPORT_R8 subject=SWOF_EVIDENCE_TRANSPORT_R8 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R8-001 subject=REQ-HGK-SWOF-W2R8-001 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R8-002 subject=REQ-HGK-SWOF-W2R8-002 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R8-003 subject=REQ-HGK-SWOF-W2R8-003 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R8-004 subject=REQ-HGK-SWOF-W2R8-004 depth=L3_INTEGRATION_RUNTIME
- ACC-REQ-HGK-SWOF-W2R8-005 subject=REQ-HGK-SWOF-W2R8-005 depth=L3_INTEGRATION_RUNTIME
- ACC-DEL-CODE subject=DEL-CODE depth=L3_INTEGRATION_RUNTIME
- ACC-DEL-EVIDENCE subject=DEL-EVIDENCE depth=L3_INTEGRATION_RUNTIME
- ACC-DEL-REPORT subject=DEL-REPORT depth=L3_INTEGRATION_RUNTIME
- ACC-UJ-R8-TRUSTED-POLICY-BOUNDARY subject=UJ-R8-TRUSTED-POLICY-BOUNDARY depth=L3_INTEGRATION_RUNTIME
- ACC-UJ-R8-RETAINED subject=UJ-R8-RETAINED depth=L3_INTEGRATION_RUNTIME
- ACC-UJ-R8-EVIDENCE subject=UJ-R8-EVIDENCE depth=L3_INTEGRATION_RUNTIME
Proxy, static, maker, shared, file-presence, or summary evidence cannot close runtime behavior.

## 7. Failure / HITL / Repair / Resume
Use the smallest affected repair, focused tests, affected regression, independent recheck, and a new checkpoint.
Require HITL for: Genuine authority edge (credential grant, visibility policy, destructive scope expansion, release/production), If trusted request owner semantics require inventing new policy absent frozen PI06 support.
No silent fallback. Use only a certified explicit substitute; otherwise return BLOCKED_EXTERNAL or BLOCKED_HITL.

## 8. Evidence / Independent acceptance / Candidate binding
Return case-specific raw receipts, command or probe, stdout/stderr/exit, producer, independent checker, source hashes, candidate head/package hash, invalidation, rollback, and residue readback.
Maker output is an evidence candidate, not a final verdict.

## 9. Termination / Final output
Terminal states: READY_FOR_W2_EXTERNAL_RECHALLENGE_ON_EXACT_R8_DUAL_SHA.
Nonterminal pauses: TEMP_CLOSED_EQUAL_RANK_EXTERNAL_CONFLICT, TEMP_CLOSED_BASELINE_IDENTITY, TEMP_CLOSED_REACHABILITY_EVIDENCE, TEMP_CLOSED_GITHUB, TEMP_CLOSED_EVIDENCE.
Iteration or session pause requires a checkpoint and is not completion.
Return no claim above LOCAL.
