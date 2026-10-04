# Generate R6 CAPC contract from R5 template (SWOF-W2-CLOSURE-R6, Branch A)
import json, copy

SRC = "C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/specs/R5_PROMPT_CONTRACT.json"
OUT = "C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/specs/R6_PROMPT_CONTRACT.json"
j = json.load(open(SRC, encoding="utf-8"))
new_source_sha = "<NEW_R6_SOURCE_SHA_ASSIGNED_POST_REPAIR>"

# --- identity / mission ---
j["task_id"] = "SWOF-W2-CLOSURE-R6"

# --- sources: R5 order becomes R6 order; add the two R5 external reports ---
src_scan_reviewed = [
    {"source_family": "current_user_instruction", "source_id": "SRC-R6-ORDER",
     "locator": "attachments/SWOF_W2_R6_Adjudication_Repair_Executor_Thin_Prompt_v1.md",
     "sha256": "UNAVAILABLE", "role": "NORMATIVE", "critical": True},
    {"source_family": "product_authority", "source_id": "SRC-PI06-DOC03",
     "locator": "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/PI-PKG/DOC/PI-PKG-06_DOC",
     "sha256": "UNAVAILABLE", "role": "NORMATIVE", "critical": True},
    {"source_family": "execution_controls", "source_id": "SRC-HGK-CONTROL",
     "locator": "C:/Projects/Agent_Workspace/HG-KSEOS/src/hg_kseos",
     "sha256": "UNAVAILABLE", "role": "NORMATIVE", "critical": True},
    {"source_family": "memory_knowledge_runtime", "source_id": "SRC-HGK-SPINE",
     "locator": "C:/Projects/Agent_Workspace/HG-KSEOS/var/shared-spine/hg-kseos.db",
     "sha256": "UNAVAILABLE", "role": "STATE_EVIDENCE", "critical": False},
    {"source_family": "external_authority", "source_id": "SRC-EXT-R5-REPORT-A",
     "locator": "attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REACCEPTANCE_REPORT_2026-10-04.md",
     "sha256": "UNAVAILABLE", "role": "NORMATIVE", "critical": True},
    {"source_family": "external_authority", "source_id": "SRC-EXT-R5-REPORT-B",
     "locator": "attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REPORT_2026-10-04.md",
     "sha256": "UNAVAILABLE", "role": "NORMATIVE", "critical": True},
]
j["source_scan"]["reviewed"] = src_scan_reviewed
j["source_scan"]["normative_claims"] = [
    {"claim_id": "NC-001", "source_ids": ["SRC-PI06-DOC03"],
     "locators": [".../PI-PKG-06_DOC"],
     "text": "DOC-03 14.R/15.2: required_authn_assurance is a REQUIRED HumanGatePolicy field (AAC1|AAC2|AAC3), owner=policy, consumer=authn validator; a caller must not supply a weaker floor."},
    {"claim_id": "NC-002", "source_ids": ["SRC-PI06-DOC03"],
     "locators": [".../PI-PKG-06_DOC"],
     "text": "DOC-03: CRITICAL=>AAC3, P4=>AAC3, P5 protected=>AAC3; effect_risk_tier owner=risk compiler, permission_class owner=permission classifier; HumanGateRequirement is deterministically policy-derived (never caller choice)."},
    {"claim_id": "NC-003", "source_ids": ["SRC-HGK-CONTROL", "SRC-R6-ORDER"],
     "locators": [".../SWOF_HGK_ACA_RBWI.md"],
     "text": "RBWI W2 exit: security/negative/adversarial + evidence envelope + checker separation for current scope; W3 remains locked until external PASS_CHALLENGE on final exact dual-SHA subject."},
]

# --- authority sources ---
auth = [
    {"id": "SRC-R6-ORDER", "rank": "R1", "role": "NORMATIVE",
     "locator": "attachments/SWOF_W2_R6_Adjudication_Repair_Executor_Thin_Prompt_v1.md",
     "sha256": "UNAVAILABLE", "governs": True,
     "path": "attachments/SWOF_W2_R6_Adjudication_Repair_Executor_Thin_Prompt_v1.md"},
    {"id": "SRC-PI06-DOC03", "rank": "R3", "role": "NORMATIVE",
     "locator": "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/PI-PKG/DOC/PI-PKG-06_DOC",
     "sha256": "UNAVAILABLE", "governs": True,
     "path": "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/PI-PKG/DOC/PI-PKG-06_DOC"},
    {"id": "SRC-RBWI", "rank": "R5", "role": "NORMATIVE",
     "locator": "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages",
     "sha256": "UNAVAILABLE", "governs": True,
     "path": "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages"},
    {"id": "SRC-HGK-CONTROL", "rank": "R6", "role": "NORMATIVE",
     "locator": "src/hg_kseos", "sha256": "UNAVAILABLE", "governs": True, "path": "src/hg_kseos"},
    {"id": "SRC-HGK-SPINE", "rank": "R7", "role": "STATE_EVIDENCE",
     "locator": "var/shared-spine/hg-kseos.db", "sha256": "UNAVAILABLE", "governs": True,
     "path": "var/shared-spine/hg-kseos.db"},
    {"id": "SRC-EXT-R5-REPORT-A", "rank": "R2", "role": "NORMATIVE",
     "locator": "attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REACCEPTANCE_REPORT_2026-10-04.md",
     "sha256": "UNAVAILABLE", "governs": True,
     "path": "attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REACCEPTANCE_REPORT_2026-10-04.md"},
    {"id": "SRC-EXT-R5-REPORT-B", "rank": "R2", "role": "NORMATIVE",
     "locator": "attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REPORT_2026-10-04.md",
     "sha256": "UNAVAILABLE", "governs": True,
     "path": "attachments/SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REPORT_2026-10-04.md"},
]
j["authority"]["sources"] = auth
j["authority"]["conflicts"] = [{
    "conflict_id": "CONF-R5-TRUSTED-POLICY-BOUNDARY-EQUAL-RANK",
    "tt_id": "TT-R6-ADJUDICATE",
    "sources": ["SRC-EXT-R5-REPORT-A", "SRC-EXT-R5-REPORT-B"],
    "equal_rank": True,
    "decision": "A_BLOCKER_CONFIRMED"
}]

# --- intent: R6 Branch A ---
j["intent"] = {
    "goal": "Execute ONE bounded W2 closure repair (R6) that deterministically adjudicates the equal-rank R5 external-conflict on whether the current W2 public HumanGate/ApprovalRequest trust boundary still permits a caller to lower policy-owned security requirements (Report A F-W2R5-EXT-001 BLOCKER_CONFIRMED), then apply the smallest repair that makes caller-supplied policy/classification fields non-authoritative: add ONE owner-injected trusted current ApprovalRequest resolver so the verifier validates decision/token against canonical request truth (rejecting any caller downgrade/mismatch, fail-closed on missing/stale/foreign), rerun focused adversarial + full regression (W1>=113, grand>=883, zero shrink), fresh independent checker attacks the trust axis, HGK exact-source reclosure with new checkpoint, publish distinct exact evidence commit (raw logs, checker transcript, immutable Return Pack with no placeholders, exact compiler receipt + thin-prompt bytes), and stop at READY_FOR_W2_EXTERNAL_RECHALLENGE — never self-issue PASS_CHALLENGE and never dispatch W3.",
    "user_expected_outcome": "F-W2R5-EXT-001 (caller-controlled canonical policy floor) closed: CRITICAL/P4/P5 with caller weaker floor is DENIED; legitimate AAC1/2/3 floors preserved (no global AAC3 force); new exact R6 source + evidence committed, independently verified, packaged for read-only external re-challenge.",
    "user_expected_experience": "User supplies the R6 order and both R5 challenge reports; adjudication, minimal repair, verification, closure and packaging proceed without repeated HITL (HITL reserved for genuine authority edges).",
    "explicit_constraints": [
        "R6 is a NARROW trust-boundary repair: caller-supplied policy/classification fields must not become authoritative policy truth merely because ApprovalRequest is a canonical dataclass",
        "Add ONE owner-injected read-only trusted current request resolver/context analogous to decision_resolver and authority_policy seams (no second HumanGatePolicy engine)",
        "Fail closed on missing resolver, absent/stale/foreign request, or any caller policy-field downgrade/mismatch",
        "Minimum trust-bound comparison set only where frozen PI06/current model supports it: operation/operation_class, effect_risk_tier, permission_class, autonomy_tier, required_authority, required_authn_assurance, rollback_ref, independent_checker_required, request_id/decision_id lineage",
        "No global AAC3 force; no restore of adapter_kind fallback; no second policy engine; direct SQL into HGK forbidden",
        "No token overrides RUIN/UNKNOWN_RUIN; closure denominator non-vacuous; no self-issued external PASS; no W3 dispatch",
        "Evidence closure mandatory (Branch B is not chosen): raw focused probes, security+full regression logs, fresh checker transcript, immutable Return Pack with real hashes (no placeholders), exact compiled thin-prompt bytes"
    ],
    "non_goals": [
        "Reopening W1 or R5 accepted local_adapter closure",
        "Redesigning HumanGate or creating a second policy engine",
        "Hard-coding global AAC3",
        "Implementing W3 product/domain journeys, coapproval, action-class, persistent-nonce before affected W3 journey activates them",
        "Performing broad security hardening without a first-failing invariant",
        "Pre-implementing W4/W5",
        "Merging PR#7; releasing; deploying; production promotion; live/world effects",
        "Self-issuing external PASS_CHALLENGE"
    ],
    "authorized_mutations": [
        "src/security/humangate.py",
        "src/security/rights.py",
        "src/security/__init__.py",
        "src/security/tests/test_humangate_currentness.py",
        "var/swof-construction-002-w2-repair-001/**"
    ],
    "forbidden_mutations": [
        "W1 accepted subject",
        "R5 closed subject (02736d3eeb6156e9763f202fbd63fff430e9eeb7 if Branch B, but Branch A changes it)",
        "HGK shared core beyond retained ChangeSet",
        "Fabric canonical contracts",
        "main branch",
        "release/production surfaces",
        "W3 dispatch"
    ],
    "expected_autonomy": "HIGH",
    "allowed_hitl": [
        "Genuine authority edge (credential grant, visibility policy, destructive scope expansion, release/production)",
        "If trusted request owner semantics require inventing new policy absent frozen PI06 support"
    ],
    "requested_delivery": ["DEL-CODE", "DEL-EVIDENCE", "DEL-REPORT"],
    "active_requirement_ids": ["REQ-HGK-SWOF-W2R6-001", "REQ-HGK-SWOF-W2R6-002",
                               "REQ-HGK-SWOF-W2R6-003", "REQ-HGK-SWOF-W2R6-004",
                               "REQ-HGK-SWOF-W2R6-005"],
    "claim_ceiling": "LOCAL"
}

# --- changeset ---
j["changeset"]["affected_domains"] = ["security", "HumanGate", "policy-owner-trust-boundary",
                                       "evidence-transport", "normative-closure"]
j["changeset"]["affected_files"] = ["src/security/humangate.py", "src/security/rights.py",
                                     "src/security/__init__.py",
                                     "src/security/tests/test_humangate_currentness.py"]
j["changeset"]["must_not_reopen"] = ["W1 implementation", "R5 local_adapter closure",
                                      "effect/assurance/observability outside cone",
                                      "provider/admission/knowledge/profile",
                                      "release/production", "W3 dispatch"]

# --- execution_scope: replace R5 capability ids with R6 ---
exec_scope = [
    {"capability": "SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY",
     "source_disposition": "SOURCE_REQUIRED", "current_execution_disposition": "ACTIVE_REQUIRED",
     "current_profile_selected": True, "canonical_flow_referenced": True,
     "automatic_route_target": True, "user_experience_required": False,
     "runtime_required_now": True, "action": "DESIGN",
     "source_locators": ["src/security/humangate.py"], "external_method": False,
     "control_authority": False},
    {"capability": "SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING",
     "source_disposition": "SOURCE_REQUIRED", "current_execution_disposition": "ACTIVE_REQUIRED",
     "current_profile_selected": True, "canonical_flow_referenced": True,
     "automatic_route_target": True, "user_experience_required": False,
     "runtime_required_now": True, "action": "DESIGN",
     "source_locators": ["src/security/humangate.py"], "external_method": False,
     "control_authority": False},
    {"capability": "HGK_EXACT_SUBJECT_CLOSURE_R6",
     "source_disposition": "SOURCE_REQUIRED", "current_execution_disposition": "ACTIVE_REQUIRED",
     "current_profile_selected": True, "canonical_flow_referenced": True,
     "automatic_route_target": True, "user_experience_required": False,
     "runtime_required_now": True, "action": "DESIGN",
     "source_locators": ["var/shared-spine"], "external_method": False,
     "control_authority": False},
    {"capability": "SWOF_EVIDENCE_TRANSPORT_R6",
     "source_disposition": "SOURCE_REQUIRED", "current_execution_disposition": "ACTIVE_REQUIRED",
     "current_profile_selected": True, "canonical_flow_referenced": True,
     "automatic_route_target": True, "user_experience_required": False,
     "runtime_required_now": True, "action": "DESIGN",
     "source_locators": ["acceptance/evidence"], "external_method": False,
     "control_authority": False},
]
j["execution_scope"] = exec_scope

# --- runtime_readiness: map ids ---
for rr in j["runtime_readiness"]:
    for key, old in [("capability","SWOF_HUMANGATE_AUTHN_FLOOR_TRUST_BOUNDARY"),
                     ("capability","SWOF_HUMANGATE_DECISION_AUTHN_LINEAGE"),
                     ("capability","HGK_EXACT_SUBJECT_CLOSURE_R5"),
                     ("capability","SWOF_EVIDENCE_TRANSPORT_R5")]:
        if rr["capability"] == old:
            rr["capability"] = {"SWOF_HUMANGATE_AUTHN_FLOOR_TRUST_BOUNDARY":"SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY",
                                "SWOF_HUMANGATE_DECISION_AUTHN_LINEAGE":"SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING",
                                "HGK_EXACT_SUBJECT_CLOSURE_R5":"HGK_EXACT_SUBJECT_CLOSURE_R6",
                                "SWOF_EVIDENCE_TRANSPORT_R5":"SWOF_EVIDENCE_TRANSPORT_R6"}[old]
    rr["acceptance_ids"] = ["ACC-" + rr["capability"]]

# --- journeys ---
j["journeys"] = [
    {"journey_id": "UJ-R6-TRUSTED-POLICY-BOUNDARY", "required": True,
     "user_goal": "A caller must never be able to lower a frozen policy-owned ApprovalRequirement (e.g. CRITICAL/P4/P5 AAC3) by constructing another ApprovalRequest with the same lineage but weaker required_authn_assurance/risk/permission/authority",
     "expected_visible_result": "verifier resolves a trusted current request and DENIES any caller policy-field downgrade/mismatch; missing/stale/foreign resolver fails closed",
     "expected_automatic_behavior": ["request_resolver(request_id) -> trusted canonical request", "caller/trusted compare on security-policy fields", "downgrade/mismatch -> DENY", "verification uses trusted request truth"],
     "expected_manual_behavior": [], "allowed_hitl": [],
     "required_capabilities": ["SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY"],
     "negative_behavior": ["trusted CRITICAL/AAC3 + caller AAC2 => DENY", "local_adapter missing floor => DENY_AUTHN"],
     "failure_recovery": ["fail closed"], "source_expectation_ids": ["SRC-PI06-DOC03"],
     "source_locators": ["src/security/humangate.py"]},
    {"journey_id": "UJ-R6-RETAINED", "required": True,
     "user_goal": "R5-closed request-floor and retained security invariants stay intact",
     "expected_visible_result": "AAC1/2/3 lattice, CRITICAL/AAC3, §15.5 basis, signed sets, P3/RUIN, unknown-op fail-closed preserved", 
     "expected_automatic_behavior": ["full regression >= 883, W1 >= 113, zero shrink"],
     "expected_manual_behavior": [], "allowed_hitl": [],
     "required_capabilities": ["SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING"],
     "negative_behavior": ["no invariant regressed"], "failure_recovery": ["fail closed"],
     "source_expectation_ids": ["SRC-PI06-DOC03"], "source_locators": ["src/security/humangate.py"]},
    {"journey_id": "UJ-R6-EVIDENCE", "required": True,
     "user_goal": "Exact R6 dual-SHA evidence handoff for read-only external re-challenge with raw logs/checker transcript and immutable Return Pack",
     "expected_visible_result": "source candidate != evidence commit; raw focused probes/regression logs/checker transcript present; immutable Return Pack with real hashes; compiler receipt + exact Compiled Thin Prompt bytes",
     "expected_automatic_behavior": ["source_candidate_sha != evidence_commit_sha", "readset out-of-tree with exact blob/commit identity"],
     "expected_manual_behavior": [], "allowed_hitl": [],
     "required_capabilities": ["SWOF_EVIDENCE_TRANSPORT_R6"],
     "negative_behavior": ["no self-issued external PASS", "no placeholder hash in Return Pack"],
     "failure_recovery": ["fail closed"], "source_expectation_ids": ["SRC-RBWI"],
     "source_locators": ["acceptance/evidence"]},
]

# --- acceptance: rebuild rows for R6 (capability/journey/req/deliverable) ---
def acc(sid, stype, loc):
    return {"acceptance_id": "ACC-" + sid, "subject_id": sid, "subject_type": stype,
            "source_locators": [loc], "runtime_required": True,
            "required_depth": "L3_INTEGRATION_RUNTIME",
            "positive_fixture": f"R6 subject {sid} reaches terminal state with bound raw evidence under the frozen R6 candidate",
            "negative_fixture": f"adversarial case for {sid} is refused fail-closed (caller cannot lower policy-owned authn floor; no silent floor)",
            "recovery_fixture": "deny/record and TEMP_CLOSED (never a fabricated closure)",
            "raw_evidence_required": True, "independent_checker_required": True,
            "terminal_states": ["INDEPENDENT_CASE_PASS"]}
pi06 = "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/PI-PKG/DOC/PI-PKG-06_DOC"
rbwi = "C:/Projects/Agent_Workspace/知識庫/實作相關DOC/Fabric vNext/Semantic World OS Fabric/SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages/SWOF_HGK_ACA_RBWI/SWOF_HGK_ACA_RBWI.md"
acc_rows = []
for c in ["SWOF_HUMANGATE_POLICY_OWNER_TRUST_BOUNDARY", "SWOF_HUMANGATE_REQUEST_LINEAGE_BINDING",
          "HGK_EXACT_SUBJECT_CLOSURE_R6", "SWOF_EVIDENCE_TRANSPORT_R6"]:
    acc_rows.append(acc(c, "CAPABILITY", pi06))
for r in ["REQ-HGK-SWOF-W2R6-001", "REQ-HGK-SWOF-W2R6-002", "REQ-HGK-SWOF-W2R6-003",
          "REQ-HGK-SWOF-W2R6-004", "REQ-HGK-SWOF-W2R6-005"]:
    acc_rows.append(acc(r, "REQUIREMENT", rbwi))
for d in ["DEL-CODE", "DEL-EVIDENCE", "DEL-REPORT"]:
    acc_rows.append(acc(d, "DELIVERABLE", rbwi))
for jid in ["UJ-R6-TRUSTED-POLICY-BOUNDARY", "UJ-R6-RETAINED", "UJ-R6-EVIDENCE"]:
    acc_rows.append(acc(jid, "JOURNEY", pi06))
j["acceptance"] = acc_rows

# --- evidence gates: R6 ---
j["evidence"] = [
    {"gate_id": "R6-G-A-COMPILE", "runtime_pass_allowed": False, "raw_receipt_required": True,
     "producer": "HERMES", "independent_checker": "HERMES-READBACK", "tracked_subject": True,
     "candidate_binding": {"head": new_source_sha, "package_sha256": new_source_sha,
                           "source_hashes": [new_source_sha]},
     "claim_level": "LOCAL", "predicate": "compiler lint/activation/acceptance/compile/duplication exit 0",
     "expected": "PROMPT_COMPILE_PASS",
     "command_or_probe": "prompt_contract_compiler.py <verb> <R6 contract>",
     "rerun_rule": "full", "invalidation": ["candidate drift", "raw missing"],
     "terminal_verdict": "PASS"},
    {"gate_id": "R6-G-B-ADJUDICATION", "runtime_pass_allowed": False, "raw_receipt_required": True,
     "producer": "HERMES", "independent_checker": "HERMES-READBACK", "tracked_subject": True,
     "candidate_binding": {"head": "02736d3eeb6156e9763f202fbd63fff430e9eeb7",
                           "package_sha256": "02736d3eeb6156e9763f202fbd63fff430e9eeb7",
                           "source_hashes": ["02736d3eeb6156e9763f202fbd63fff430e9eeb7"]},
     "claim_level": "LOCAL", "predicate": "deterministic equal-rank adjudication A1-A6 + full-route counterexample (T1/T2 APPROVE under CRITICAL=>AAC3)",
     "expected": "A_BLOCKER_CONFIRMED", "command_or_probe": "R6_POLICY_TRUST_ADJUDICATION.json",
     "rerun_rule": "full", "invalidation": ["candidate drift", "raw missing"],
     "terminal_verdict": "PASS"},
    {"gate_id": "R6-G-C-REPAIR", "runtime_pass_allowed": False, "raw_receipt_required": True,
     "producer": "HERMES", "independent_checker": "HERMES-READBACK", "tracked_subject": True,
     "candidate_binding": {"head": new_source_sha, "package_sha256": new_source_sha,
                           "source_hashes": [new_source_sha]},
     "claim_level": "LOCAL",
     "predicate": "trusted request resolver seam added; caller policy-field downgrade denied; no global AAC3; adapter_kind still inert",
     "expected": "PASS", "command_or_probe": "src/security/humangate.py + rights.py + focused tests",
     "rerun_rule": "full", "invalidation": ["candidate drift", "raw missing"],
     "terminal_verdict": "PASS"},
    {"gate_id": "R6-G-D-REGRESSION", "runtime_pass_allowed": False, "raw_receipt_required": True,
     "producer": "HERMES", "independent_checker": "HERMES-READBACK", "tracked_subject": True,
     "candidate_binding": {"head": new_source_sha, "package_sha256": new_source_sha,
                           "source_hashes": [new_source_sha]},
     "claim_level": "LOCAL",
     "predicate": "W1>=113, grand>=883 (report new denominator honestly if tests added), zero shrink, all exit 0",
     "expected": "PASS", "command_or_probe": "R6_FULL_REGRESSION_INDEX.json + raw root logs",
     "rerun_rule": "full", "invalidation": ["candidate drift", "raw missing"],
     "terminal_verdict": "PASS"},
    {"gate_id": "R6-G-E-CHECKER", "runtime_pass_allowed": False, "raw_receipt_required": True,
     "producer": "HERMES", "independent_checker": "ACCEPTANCE-OFFICER-FRESH-CONTEXT-VERIFY-ONLY",
     "tracked_subject": True,
     "candidate_binding": {"head": new_source_sha, "package_sha256": new_source_sha,
                           "source_hashes": [new_source_sha]},
     "claim_level": "LOCAL",
     "predicate": "fresh-context VERIFY_ONLY checker attacks call-controlled policy downgrade axis; checker != maker; raw transcript present",
     "expected": "PASS", "command_or_probe": "R6_FRESH_CHECKER_RECEIPT.json + transcript",
     "rerun_rule": "full", "invalidation": ["candidate drift", "raw missing"],
     "terminal_verdict": "PASS"},
    {"gate_id": "R6-G-F-CLOSURE", "runtime_pass_allowed": False, "raw_receipt_required": True,
     "producer": "HERMES", "independent_checker": "HERMES-READBACK", "tracked_subject": True,
     "candidate_binding": {"head": new_source_sha, "package_sha256": new_source_sha,
                           "source_hashes": [new_source_sha]},
     "claim_level": "LOCAL",
     "predicate": "typed HGK exact-source reclosure with NEW checkpoint; blocking_open=0; non-vacuous denominator; no direct SQL",
     "expected": "PASS", "command_or_probe": "R6_W2_NORMATIVE_CLOSURE_PROJECTION.json",
     "rerun_rule": "full", "invalidation": ["candidate drift", "raw missing"],
     "terminal_verdict": "PASS"},
]

# --- termination ---
j["termination"] = {
    "terminal_states": ["READY_FOR_W2_EXTERNAL_RECHALLENGE_ON_EXACT_R6_DUAL_SHA"],
    "non_terminal_pause": ["TEMP_CLOSED_EQUAL_RANK_EXTERNAL_CONFLICT", "TEMP_CLOSED_BASELINE_IDENTITY",
                            "TEMP_CLOSED_REACHABILITY_EVIDENCE", "TEMP_CLOSED_GITHUB",
                            "TEMP_CLOSED_EVIDENCE"],
    "checkpoint_required": True,
    "checkpoint_fields": ["task_id", "source_hashes", "current_candidate", "completed_gates",
                          "open_gates", "next_work_order", "rollback_pointer"],
    "retry_budget": 1, "rollback_pointer_required": True}

json.dump(j, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
import hashlib
print("WROTE", OUT)
print("sha256:", hashlib.sha256(open(OUT,'rb').read()).hexdigest()[:16])
print("task_id:", j["task_id"], "| conflict:", j["authority"]["conflicts"][0]["decision"], "| acc rows:", len(j["acceptance"]))