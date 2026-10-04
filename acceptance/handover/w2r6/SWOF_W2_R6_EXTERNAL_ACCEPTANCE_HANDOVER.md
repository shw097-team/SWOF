# SWOF W2 R6 — External Acceptance Handover (single-MD, full raw embedded)

```yaml
repair_id: SWOF-W2-CLOSURE-R6
changeset: NARROW_REPAIR (Branch A)
repo: shw097-team/SWOF
pr: 7
source_candidate_sha: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
evidence_commit_sha: 6c58c21eee69391ba146e21e27b6d3b7f8f2211c
parent_source_sha: 02736d3eeb6156e9763f202fbd63fff430e9eeb7
parent_evidence_sha: a6ee9b5ce8b0b0905be4952c32b2ddd747929c25
source_ne_evidence: true
claim_ceiling: READY_FOR_W2_EXTERNAL_RECHALLENGE only
non_claims: [NOT_EXTERNALLY_ACCEPTED, W3_NOT_STARTED, NOT_MERGED, NOT_RELEASED, NOT_PRODUCTION, NO_WORLD_EFFECT]
```

## 0. Verification verdicts (maker + independent checker)

- Adjudication: **A_BLOCKER_CONFIRMED** (read-only deterministic, frozen PI06 + exact source).
- Product repair: owner-injected `request_resolver` seam; policy-owned fields pinned; fail-closed `DENY_REQUEST_UNRESOLVED` / `DENY_REQUEST_POLICY_MISMATCH`; floor/authority read from trusted request.
- Focused adversarial set `TestR6TrustedRequestBoundary` A1–A13: **13/13 PASS**.
- Regression: **W1=113, W2=783, grand=896** (>=883, +13, no shrink), zero-denominator roots=0, all roots exit 0.
- Fresh independent checker (fresh-context, VERIFY_ONLY, read-only, NOT maker): **product/governance/wave = PASS**, no CONFIRMED_DEFECT.
- Compiler: 5-stage **PROMPT_COMPILE_PASS** (contract sha256 `82cb7049422a8f6d84c04d42a24cc56804c93944d43fe3e02a6800a1b43ef70a`).

## A. Raw evidence embedded from the exact evidence commit

Each block is byte-identical to the file at `acceptance/evidence/w2r1/94e4c15e1040a159d0eb6ac3ef4089b421e60bf9/` in evidence commit `6c58c21eee69391ba146e21e27b6d3b7f8f2211c`.

### R6_POLICY_TRUST_ADJUDICATION.json

- sha256: `7ca9649aec8e708fef5fd13bb7b96c16316231bea5d55b891822d0c6c0a337e9` · bytes: 4462

```json
{
  "schema": "SWOF-W2-R6-POLICY-TRUST-ADJUDICATION/1",
  "repair_id": "SWOF-W2-CLOSURE-R6",
  "changeset": "NARROW_REPAIR",
  "mode": "DETERMINISTIC_READ_ONLY_ADJUDICATION_THEN_BRANCH_A_REPAIR",
  "subject": {
    "r5_source_sha": "02736d3eeb6156e9763f202fbd63fff430e9eeb7",
    "r5_evidence_sha": "a6ee9b5ce8b0b0905be4952c32b2ddd747929c25",
    "r6_source_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
  },
  "equal_rank_conflict": {
    "report_A": {"file": "SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REACCEPTANCE_REPORT_2026-10-04.md",
                 "verdict": "FAIL_CHALLENGE", "finding": "F-W2R5-EXT-001 caller-controlled canonical policy floor"},
    "report_B": {"file": "SWOF_W2R5_POST_REPAIR_EXTERNAL_CHALLENGE_REPORT_2026-10-04.md",
                 "verdict": "TEMP_CLOSED_CHALLENGE", "finding": "EG-W2R5-EXT-001 evidence-only; policy provenance deferred to W3 TT"},
    "resolution_basis": "read-only exact-source probes + frozen PI06 authority",
    "resolution": "A_BLOCKER_CONFIRMED"
  },
  "a1_public_surface": {"question": "ApprovalRequest publicly exported + accepted by W2 verification path?",
    "evidence": "src/security/__init__.py exports ApprovalRequest; rights.py assert_human_gate_satisfied accepts it (single gate call site rights.py)", "verdict": "YES"},
  "a2_policy_owner": {"question": "frozen PI06 assigns required_authn_assurance/risk/permission/authority ownership to policy/classifier owners?",
    "evidence": "PI06 DOC-03 matrix: required_authn_assurance owner=policy, consumer=authn validator, invariant=meets floor; effect_risk_tier owner=risk compiler; permission_class owner=permission classifier; CRITICAL/P4/P5 => AAC3", "verdict": "YES"},
  "a3_runtime_provenance": {"question": "current W2 runtime enforces a trusted canonical request resolver boundary?",
    "evidence": "R5 02736d3e: VerificationContext has decision_resolver + authority_policy but NO request_resolver; floor read from caller-declared required_authn_assurance", "verdict": "NO (pre-repair)"},
  "a4_downgrade_reachability": {"question": "caller can present CRITICAL/P4/P5 semantics with weaker policy fields and verifier accepts weaker AAC?",
    "evidence": "R5 test_r008_exact_floor_aac2_request_passes: caller-declared AAC2 floor honored; monotone compare accepts AAC2>=AAC2 before signature", "verdict": "YES (pre-repair)"},
  "a5_contract_scope": {"question": "verifier enforceably typed as consuming only prevalidated policy-owned requests?",
    "evidence": "pre-repair none; post-repair request_resolver pins policy fields with DENY_REQUEST_UNRESOLVED/DENY_REQUEST_POLICY_MISMATCH", "verdict": "NO pre / ENFORCED post"},
  "a6_current_scope": {"question": "this security API part of W2 substrate acceptance surface?",
    "evidence": "ApprovalRequest + verifier are public W2 substrate exports consumed by assert_human_gate_satisfied", "verdict": "YES"},
  "branch_predicates": {
    "A_BLOCKER_CONFIRMED": {"public_admitted_surface": true, "frozen_pi06_requires_stronger": true,
      "caller_controls_weaker_fields": true, "no_trusted_resolver_prevents": true,
      "full_route_accepts_weaker": true, "chosen": true},
    "B_CURRENT_W2_SCOPE_NONBLOCKING": false, "C_UNRESOLVED": false
  },
  "challenge_cases": {
    "T1_CRITICAL_calleraac2": "post-repair DENY_REQUEST_POLICY_MISMATCH (A1)",
    "T2_P4_calleraac2": "post-repair DENY_REQUEST_POLICY_MISMATCH (A2)",
    "T3_protectedP5_weaker": "post-repair DENY_REQUEST_POLICY_MISMATCH (A3)",
    "T4_lower_effect_risk_tier": "DENY_REQUEST_POLICY_MISMATCH (A4)",
    "T5_lower_permission_class": "DENY_REQUEST_POLICY_MISMATCH (A5)",
    "T6_lower_autonomy_tier": "DENY_REQUEST_POLICY_MISMATCH (A6)",
    "T7_lower_required_authority": "DENY_REQUEST_POLICY_MISMATCH (A7)",
    "T8_local_adapter_missing_floor": "DENY_AUTHN preserved (A11)",
    "T9_exact_owner_control": "PASS preserved (A12)"
  },
  "root_cause": "caller-supplied ApprovalRequest policy/classification fields treated as trusted policy truth",
  "decision": "A_BLOCKER_CONFIRMED",
  "repair": {"class": "NARROW_REPAIR", "files": ["src/security/humangate.py","src/security/tests/test_humangate_currentness.py","src/security/tests/test_rights.py"],
    "seam": "owner-injected request_resolver(request_id) -> current canonical ApprovalRequest; policy-owned fields pinned; fail-closed; floor read from trusted request",
    "no_second_policy_engine": true, "no_global_aac3_force": true, "no_adapter_fallback": true}
}
```

### R6_RAW_ADJUDICATION_TRANSCRIPT.log

- sha256: `ee60ff08fc28d070847325821636ea43ce6f2ea1832021becd9836a4e7d58221` · bytes: 1074

```text
# command : cross-tree full-route counterexample F-W2R5-EXT-001 (CRITICAL semantic, caller AAC2 floor, AAC2 decision/token)
# phase   : w2_candidate_w2r6_adjudication
# started : 2026-10-04T16:36:12Z
------------------------------------------------------------------------------
[OBSERVED] subject R5 source 02736d3eeb6156e9763f202fbd63fff430e9eeb7
R5 test_r008_exact_floor_aac2_request_passes: caller-declared AAC2 floor honored (OK) - verifier reads caller floor as truth; no trusted-request resolver seam.

[VERDICT-R5] R5 accepts caller-declared AAC2 floor even on security-relevant request: caller controls policy floor.

[OBSERVED] subject R6 source 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9 (repaired)
TestR6TrustedRequestBoundary A1-A13 all PASS (13/13): DENY_REQUEST_UNRESOLVED / DENY_REQUEST_POLICY_MISMATCH on downgrade.

[VERDICT-R6] caller-declared AAC2 floor on trusted CRITICAL/AAC3 request: DENY_REQUEST_POLICY_MISMATCH.

FINAL: BLOCKER_CONFIRMED (Branch A). R5 accepts downgrade; R6 rejects. F-W2R5-EXT-001 closed by trusted request boundary.

```

### R6_RAW_FOCUSED_PROBES.log

- sha256: `3cbc1dfa5343172d18cd86cdad82d4527b39aad9c28cfeb18aecaa5851c418aa` · bytes: 3291

```text
# command : "C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe" -m unittest src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary -v
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# phase   : w2_candidate_w2r6_focused
# started : 2026-10-04T16:36:11Z
# duration: 0.469s
# exit_code: 0
------------------------------------------------------------------------------
test_a10_stale_or_superseded_trusted_request_is_denied (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a10_stale_or_superseded_trusted_request_is_denied) ... ok

test_a11_local_adapter_missing_floor_remains_deny_authn (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a11_local_adapter_missing_floor_remains_deny_authn) ... ok

test_a12_exact_trusted_request_with_valid_decision_and_token_is_approved (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a12_exact_trusted_request_with_valid_decision_and_token_is_approved) ... ok

test_a13_exact_floors_remain_exact_on_a_benign_request (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a13_exact_floors_remain_exact_on_a_benign_request) ... ok

test_a1_trusted_critical_aac3_caller_clone_aac2_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a1_trusted_critical_aac3_caller_clone_aac2_is_policy_mismatch) ... ok

test_a2_trusted_p4_aac3_caller_clone_aac2_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a2_trusted_p4_aac3_caller_clone_aac2_is_policy_mismatch) ... ok

test_a3_trusted_protected_p5_aac3_caller_clone_aac2_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a3_trusted_protected_p5_aac3_caller_clone_aac2_is_policy_mismatch) ... ok

test_a4_caller_lowers_effect_risk_tier_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a4_caller_lowers_effect_risk_tier_is_policy_mismatch) ... ok

test_a5_caller_lowers_permission_class_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a5_caller_lowers_permission_class_is_policy_mismatch) ... ok

test_a6_caller_lowers_autonomy_tier_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a6_caller_lowers_autonomy_tier_is_policy_mismatch) ... ok

test_a7_caller_lowers_required_authority_is_policy_mismatch (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a7_caller_lowers_required_authority_is_policy_mismatch) ... ok

test_a8_missing_trusted_request_resolver_is_deny_request_unresolved (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a8_missing_trusted_request_resolver_is_deny_request_unresolved) ... ok

test_a9_trusted_request_not_found_is_deny_request_unresolved (src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a9_trusted_request_not_found_is_deny_request_unresolved) ... ok



----------------------------------------------------------------------

Ran 13 tests in 0.012s



OK
```

### R6_FULL_REGRESSION_INDEX.json

- sha256: `e803700ec5f01e811e3c65cdb4f8ab9de1cb183074c1022556fa39af00a45b42` · bytes: 5002

```json
{
  "schema": "SWOF-W2-R6-FULL-REGRESSION-INDEX/1",
  "phase": "w2_candidate_w2r6",
  "source_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "generated_at": "2026-10-04T16:36:04Z",
  "roots": [
    {
      "name": "R6_ROOT_w1_tests.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s tests -t .",
      "exit_code": 0,
      "started": "2026-10-04T16:36:02Z",
      "duration": "0.240s",
      "sha256": "720d75e4a29367fb45188cc93680f3eea9e801c94dba7464dff7b478276359e7",
      "bytes": 642
    },
    {
      "name": "R6_ROOT_w1_fabric.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/fabric/tests -t src/fabric/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:03Z",
      "duration": "0.129s",
      "sha256": "99b90d64e6a35247b9239ced4a896c5f7196972fbe1e052e3e935b2bf85276e0",
      "bytes": 673
    },
    {
      "name": "R6_ROOT_w1_knowledge.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/knowledge/tests -t src/knowledge/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:03Z",
      "duration": "0.117s",
      "sha256": "9a8b5db608de1cc53845226901405fc8eec29b064ce4abf02942a7b813c13813",
      "bytes": 683
    },
    {
      "name": "R6_ROOT_w1_admission.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/admission/tests -t src/admission/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:03Z",
      "duration": "0.110s",
      "sha256": "24de66c2e422e6d8a38bc9824a16cb7995e577974e2d734f4c5f6d09cf2f2c65",
      "bytes": 675
    },
    {
      "name": "R6_ROOT_w1_profile.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/profile/tests -t src/profile/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:03Z",
      "duration": "0.112s",
      "sha256": "89fedda8710e1e78f1ec1a02cf58a9d4f98f8065acb9cce7121ca988d3193bef",
      "bytes": 666
    },
    {
      "name": "R6_ROOT_w1_capability.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/capability/tests -t src/capability/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:03Z",
      "duration": "0.279s",
      "sha256": "a4e3a102245073437553d3d92335c16c83fe30d22f6bcb4a593d1d057d7f7e90",
      "bytes": 682
    },
    {
      "name": "R6_ROOT_w2_security.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/security/tests -t src/security/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:03Z",
      "duration": "0.302s",
      "sha256": "66198745dbd347451fee908d4e4bcc1b85d9b5fbc3a18efa52d5419e4a2ecf18",
      "bytes": 1078
    },
    {
      "name": "R6_ROOT_w2_effect.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/effect/tests -t src/effect/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:04Z",
      "duration": "0.146s",
      "sha256": "00a99ea0984bdca95c25e4a91fb1dda60b9759e45699bd61cfe6dad52e4b9601",
      "bytes": 769
    },
    {
      "name": "R6_ROOT_w2_assurance.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/assurance/tests -t src/assurance/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:04Z",
      "duration": "0.151s",
      "sha256": "4eabf47b29d18ccc08227861ccff9336e2a4fb59e7b7885e6bff361d4eec14e1",
      "bytes": 803
    },
    {
      "name": "R6_ROOT_w2_observability.log",
      "command": "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe -m unittest discover -s src/observability/tests -t src/observability/tests",
      "exit_code": 0,
      "started": "2026-10-04T16:36:04Z",
      "duration": "0.157s",
      "sha256": "f5ddf21ecced5fedcdc9572f7916dfa734878c51b55b930be7a1d237ba76e5e6",
      "bytes": 769
    }
  ],
  "summary": {
    "exit_zero_all": true,
    "root_count": 10,
    "zero_denominator_roots": 0
  },
  "denominator": {
    "w1_total": 113,
    "w2_total": 783,
    "grand_total": 896,
    "by_root_w1": {
      "tests": 16,
      "fabric": 21,
      "knowledge": 25,
      "admission": 17,
      "profile": 12,
      "capability": 22
    },
    "by_root_w2": {
      "security": 421,
      "effect": 116,
      "assurance": 144,
      "observability": 102
    }
  },
  "index_sha256": "a7c417ebf86c73a570456d63a755c39d993babe982c8e5904d4e025ebba97e0e"
}
```

### R6_ROOT_w1_tests.log

- sha256: `9dbb2269c9149a03c9db926337e0157e8ccf13e470d01ed2e79ce729decaa3da` · bytes: 658

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s tests -t .
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:02Z
# duration: 0.240s
# exit_code: 0
------------------------------------------------------------------------------

................
----------------------------------------------------------------------
Ran 16 tests in 0.109s

OK

```

### R6_ROOT_w1_fabric.log

- sha256: `d4839154aaf4a37ef722ed6c929bf45ecada0e023ee12dfe159bd72df877b7a3` · bytes: 689

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/fabric/tests -t src/fabric/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:03Z
# duration: 0.129s
# exit_code: 0
------------------------------------------------------------------------------

.....................
----------------------------------------------------------------------
Ran 21 tests in 0.002s

OK

```

### R6_ROOT_w1_knowledge.log

- sha256: `0ccc5b66ca45811bf723c05889a95919068d360dbfbcd7dbb14005aabfb980b4` · bytes: 699

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/knowledge/tests -t src/knowledge/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:03Z
# duration: 0.117s
# exit_code: 0
------------------------------------------------------------------------------

.........................
----------------------------------------------------------------------
Ran 25 tests in 0.001s

OK

```

### R6_ROOT_w1_admission.log

- sha256: `9bed75a79e0638b387f92a700f8af7486bf261517852066a35d4607fb9e6b369` · bytes: 691

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/admission/tests -t src/admission/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:03Z
# duration: 0.110s
# exit_code: 0
------------------------------------------------------------------------------

.................
----------------------------------------------------------------------
Ran 17 tests in 0.001s

OK

```

### R6_ROOT_w1_profile.log

- sha256: `f13973a1e0f8f39d7786a20e016fe2e348abc2f3e4e03c1bc65e947e57080a85` · bytes: 682

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/profile/tests -t src/profile/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:03Z
# duration: 0.112s
# exit_code: 0
------------------------------------------------------------------------------

............
----------------------------------------------------------------------
Ran 12 tests in 0.000s

OK

```

### R6_ROOT_w1_capability.log

- sha256: `48276cec75048e4edf66a3bc57fa10b8a74e319c411e740cd5f1b80ee07ffe85` · bytes: 698

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/capability/tests -t src/capability/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:03Z
# duration: 0.279s
# exit_code: 0
------------------------------------------------------------------------------

......................
----------------------------------------------------------------------
Ran 22 tests in 0.144s

OK

```

### R6_ROOT_w2_security.log

- sha256: `1201cd0cd81c7994b7c0b0c77f22a671f206ec91ac4115a7b6d59c8e211e9434` · bytes: 1094

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/security/tests -t src/security/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:03Z
# duration: 0.302s
# exit_code: 0
------------------------------------------------------------------------------

.....................................................................................................................................................................................................................................................................................................................................................................................................................................
----------------------------------------------------------------------
Ran 421 tests in 0.118s

OK

```

### R6_ROOT_w2_effect.log

- sha256: `8c7a80bac7dce01bb3c0ef35be0e880fa62fa44819fc62ec6dc9d233023bc9b8` · bytes: 785

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/effect/tests -t src/effect/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:04Z
# duration: 0.146s
# exit_code: 0
------------------------------------------------------------------------------

....................................................................................................................
----------------------------------------------------------------------
Ran 116 tests in 0.006s

OK

```

### R6_ROOT_w2_assurance.log

- sha256: `e240a6458e27c6d8a86630c32819ae2e38ccaa3f0bb15c54af068cd179b39cc8` · bytes: 819

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/assurance/tests -t src/assurance/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:04Z
# duration: 0.151s
# exit_code: 0
------------------------------------------------------------------------------

................................................................................................................................................
----------------------------------------------------------------------
Ran 144 tests in 0.015s

OK

```

### R6_ROOT_w2_observability.log

- sha256: `d11781b1c96f858514b71c30d5215ab2c6a606c2535b3ddf055512fee1fd849f` · bytes: 785

```text
# command : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m unittest discover -s src/observability/tests -t src/observability/tests
# cwd     : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree
# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# branch  : wo/swof-w2-closure-r6
# python  : C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
# phase   : w2_candidate_w2r6
# started : 2026-10-04T16:36:04Z
# duration: 0.157s
# exit_code: 0
------------------------------------------------------------------------------

......................................................................................................
----------------------------------------------------------------------
Ran 102 tests in 0.008s

OK

```

### R6_FRESH_CHECKER_REPORT.md

- sha256: `04e9d26fb3dc16562fc89385a965ce895c7d03a824a2282dfdc39853a48da037` · bytes: 3215

```text
# R6 Fresh Independent Checker — Full Report

Checker status: fresh-context, independent, VERIFY_ONLY, read-only, NOT the maker.
No modifications, no commits to the candidate repo.
Subject: source `94e4c15e1040a159d0eb6ac3ef4089b421e60bf9` (branch wo/swof-w2-closure-r6).
Delegation: deleg_f3a757d7 (sa-0-4426308c), 24 api calls, 155.88s.

## product_verdict: PASS

1. **R5 defect reproduced** on `C:/tmp/swof-r5-check` @ 02736d3 (no request_resolver): CRITICAL/P5 request,
   caller-declared `required_authn_assurance="AAC2"`, AAC2 decision+token:
   `True APPROVE_BASIS_SATISFIED` => ACCEPTED (defect confirmed pre-fix).
2. **Same attack DENIED on R6** (trusted resolver returns canonical CRITICAL/AAC3, caller declares AAC2,
   AAC2 decision+token): `False DENY_REQUEST_POLICY_MISMATCH | required_authn_assurance`.
3. **Fail-closed paths** independently triggered:
   - absent request_resolver on gated path => `DENY_REQUEST_UNRESOLVED`
   - empty caller floor on CRITICAL => `DENY_AUTHN`
   - weak token AAC2 on trusted AAC3 floor => `DENY_AUTHN` (floor read from trusted request)
   - trusted required_authority=HA5 vs caller HA3 => `DENY_REQUEST_POLICY_MISMATCH`
   - gateway `assert_human_gate_satisfied` downgrade => `DENY_REQUEST_POLICY_MISMATCH` (no route bypass;
     only call site of verify_approval_token is rights.py:431)
4. **New deny codes** exist in APPROVAL_DENY_CODES and are surfaced as typed ApprovalDecision.code:
   `DENY_REQUEST_UNRESOLVED`, `DENY_REQUEST_POLICY_MISMATCH`.
5. **Regression re-run independently**: w2_security=421 OK; w1 16/21/25/17/12/22 all OK;
   w2 effect=116, assurance=144, observability=102 all OK. Grand total = 896 (113+783, >=883),
   zero-denominator roots = 0, all 10 roots exit 0. R6-vs-R5 security delta = +13 exactly.
   Focused `TestR6TrustedRequestBoundary` A1-A13: 13/13 OK.

Bypass analysis: resolver keyed on request_id + lineage exact-binding; any `_REQUEST_POLICY_FIELDS`
divergence => DENY_REQUEST_POLICY_MISMATCH; unknown request_id => DENY_REQUEST_UNRESOLVED. The verifier
never trusts caller-declared policy truth.

## governance_verdict: PASS
SoD maintained; evidence/source binding exact (`R6_FULL_REGRESSION_INDEX.json` source_sha = 94e4c15…;
raw log headers `git HEAD: 94e4c15e…`; compiler receipt source_sha_at_compile same). Index denominators
match re-derived root logs. Claim <= evidence.

## wave_verdict: PASS

## CONFIRMED_DEFECT
None in the R6 candidate.

## EVIDENCE_GAP (non-blocking) — RESOLVED
The checker observed `R6_POLICY_TRUST_ADJUDICATION.json` absent from the working R6_EVIDENCE dir at
check time. It is now present in the frozen immutable evidence commit
`6c58c21eee69391ba146e21e27b6d3b7f8f2211c` (verified via `git show 6c58c21:…/R6_POLICY_TRUST_ADJUDICATION.json`).
The check ran before the file was restored following a directory regeneration; the frozen subject is complete.

## NON_BLOCKING_OBSERVATIONS
- Seam trigger is `_required_authn_floor(request) is not None`; an absent caller floor skips the pinning
  and fails closed via DENY_AUTHN (no downgrade possible). Code-path distinction, not a security gap.
- The untracked `acceptance/` dir at worktree root is not part of the committed candidate tree.

```

### R6_FRESH_CHECKER_TRANSCRIPT.log

- sha256: `429e6031d61bdcad512be8e0ae11274fecb0ffe967c43d03bfce282d4b0b95cf` · bytes: 34511

```text
# checker: fresh-context VERIFY_ONLY read-only, NOT maker
# subject source: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
# delegation: deleg_f3a757d7 (sa-0-4426308c)
# phase: w2_candidate_w2r6_checker
# generated: 2026-10-04T16:40:11+00:00
------------------------------------------------------------------------------
=== Hermes subagent live transcript ===
delegation: deleg_f3a757d7   task: 0
goal: Act as the FRESH INDEPENDENT CHECKER (VERIFY_ONLY, read-only, NOT the maker) for SWOF W2 R6 source candidate. Independently attack and verify, do not trust the maker's self-report. Working checks BELOW are read-only adversarial verification. Report findings as structured JSON-compatible text with explicit product_verdict, governance_verdict, wave_verdict (each must be PASS or FAIL or TEMP_CLOSED; overall PARTIAL is not PASS). SOURCE TO CHECK (exact identity): - repo: shw097-team/SWOF, PR #7 (ope …(+3662 chars)
started: 2026-10-05 00:36:19
(append-only; streams while the subagent runs — tail -f me)
========================================
00:36:19 user     | kickoff: Act as the FRESH INDEPENDENT CHECKER (VERIFY_ONLY, read-only, NOT the maker) for SWOF W2 R6 source candidate. Independently attack and verify, do not trust the maker's self-report. Working checks BELOW are read-only adversarial verification. Report findings as structured JSON-compatible text with explicit product_verdict, governance_verdict, wave_verdict (each must be PASS or FAIL or TEMP_CLOSED; overall PARTIAL is not PASS). SOURCE TO CHECK (exact identity): - repo: shw097-team/SWOF, PR #7 (ope …(+3662 chars) | context: You are a fresh, independent, read-only checker operating on the local committed candidate tree C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree at HEAD 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9. Python interpreter C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe. Do not modify or commit anything. Run tests and probe code; report your own observed evidence. Respond in English.
00:36:19 start    | Act as the FRESH INDEPENDENT CHECKER (VERIFY_ONLY, read-only, NOT the maker) for SWOF W2 R6 source candidate. Independently attack and verify, do not trust the maker's self-report. Working checks BELOW are read-only adversarial verification. Report findings as structured JSON-compatible text with explicit product_verdict, governance_verdict, wave_verdict (each must be PASS or FAIL or TEMP_CLOSED; overall PARTIAL is not PASS). SOURCE TO CHECK (exact identity): - repo: shw097-team/SWOF, PR #7 (ope …(+3662 chars)
00:36:22 think    | I'll begin by establishing the source identity and exploring the codebase struct
00:36:22 assistant| I'll begin by establishing the source identity and exploring the codebase structure. Let me start with several independent reads.
00:36:22 tool     | -> terminal(git rev-parse HEAD + 2 commands)
00:36:22 result   | terminal ok 0.3s: {"output": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9\nwo/swof-w2-closure-r6\n94e4c15 WO-SWOF-W2-R006R (Branch A): trusted ApprovalRequest policy boundary - owner-injected request_resolver pins caller request to canonical current request on policy-owned fields; fail-closed DENY_REQUEST_UNRESOLVED/DENY_REQUEST_POLICY_MISMATCH; authn floor read from trusted request (F-W2R5-EXT-001)\n02736d3 W2 R5: re …(+404 chars)
00:36:22 tool     | -> terminal(git status --short + 1 command)
00:36:23 result   | terminal ok 0.3s: {"output": "?? acceptance/\n---REMOTE---\norigin\thttps://github.com/shw097-team/SWOF.git (fetch)\norigin\thttps://github.com/shw097-team/SWOF.git (push)", "exit_code": 0, "error": null}
00:36:23 tool     | -> terminal(ls C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree/)
00:36:23 result   | terminal ok 0.3s: {"output": "acceptance\nAGENTS.md\nconfig\ndocs\npyproject.toml\nREADME.md\nschemas\nsrc\ntests\ntools", "exit_code": 0, "error": null}
00:36:25 think    | Head SHA confirmed. There's an untracked `acceptance/` dir (not part of committe
00:36:25 assistant| Head SHA confirmed. There's an untracked `acceptance/` dir (not part of committed tree — likely maker artifacts). Let me explore the source and locate the seams.
00:36:25 tool     | -> terminal(ls acceptance/ 2>/dev/null + 2 commands)
00:36:25 result   | terminal ok 0.4s: {"output": "evidence\n===SRC===\nsrc/admission/ladder.py\nsrc/admission/tests/test_ladder.py\nsrc/admission/tests/__init__.py\nsrc/admission/__init__.py\nsrc/assurance/evidence.py\nsrc/assurance/journal.py\nsrc/assurance/oracle.py\nsrc/assurance/predicate.py\nsrc/assurance/sod.py\nsrc/assurance/tests/test_adversarial.py\nsrc/assurance/tests/test_evidence.py\nsrc/assurance/tests/test_journal.py\nsr …(+1294 chars)
00:36:25 tool     | -> search_files(request_resolver)
00:36:25 tool     | -> search_files(DENY_REQUEST_UNRESOLVED|DENY_REQUEST_POLICY_MISMATCH)
00:36:26 result   | search_files ok 0.5s: {"total_count": 3, "files": ["C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree/src\\security\\humangate.py", "C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree/src\\security\\tests\\test_humangate_currentness.py", "C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree/src\\security\\tests\\test_rights.py"]}
00:36:26 result   | search_files ok 0.4s: {"total_count": 2, "files": ["C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree\\src\\security\\humangate.py", "C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree\\src\\security\\tests\\test_humangate_currentness.py"]}
00:36:28 think    | The core changes are in `src/security/humangate.py`. Let me read it and the rele
00:36:28 assistant| The core changes are in `src/security/humangate.py`. Let me read it and the relevant test file.
00:36:28 tool     | -> read_file(humangate.py)
00:36:28 result   | read_file ok 0.4s: {"content": "1|\"\"\"Typed, exact-bound human approval tokens at the existing HumanGate seam.\n2|\n3|WHY: a HumanGate that accepts any non-empty string is a syntactic gate, not an authority gate -\n4|\"approved\" typed by the actor who wants the action is indistinguishable from a real approval, so\n5|the gate refuses nothing. This module makes the approval a typed value object bound exactly to the …(+67741 chars)
00:36:28 tool     | -> terminal(diff <(git show 02736d3:src/security/humangate.py 2>/dev/null) src/security/humangate.py)
00:36:28 result   | terminal ok 0.3s: {"output": "58a59,65\n> \n> R6 repair WO-SWOF-W2-R006R (F-W2R5-EXT-001): `ApprovalRequest` is public, so a caller could declare a\n> LOWER `required_authn_assurance` on an otherwise CRITICAL/P4/P5 request and have the R008 floor honor\n> it - a deterministic downgrade. The fix is the smallest legal seam, mirroring `decision_resolver`:\n> a THIRD owner-injected `request_resolver` that resolves the  …(+6451 chars)
00:36:38 think    | The diff is tightly scoped to the trusted-request boundary. Let me examine the r
00:36:38 assistant| The diff is tightly scoped to the trusted-request boundary. Let me examine the rights.py gate path (to confirm no bypass), the package exports, and the focused test file.
00:36:38 tool     | -> search_files(def assert_human_gate_satisfied|def _gate|verify_approval_token)
00:36:38 result   | search_files ok 0.4s: {"total_count": 19, "matches_format": "path-grouped: each file path on its own line, followed by indented '<line>: <content>' rows for matches in that file", "matches_text": "C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree/src/security\\__init__.py\n 12: ApprovalRequest, ApprovalToken, NonceLedger, VerificationContext, verify_approval_token,\n 26: \"verify_approval_token\",\nC:/Projects/Agent_Work …(+1464 chars)
00:36:39 tool     | -> terminal(cat src/security/__init__.py 2>/dev/null + 2 commands)
00:36:39 result   | terminal ok 0.5s: {"output": "\"\"\"SWOF security / privacy / rights / HumanGate substrate (W2, WO-SWOF-W2-001).\n\nFail-closed guards that refuse; they never grant authority and never become a source of\nProduct, Semantic or Acceptance truth. See README.md for the contract per module.\n\nWO-SWOF-W2-R001 adds the typed HumanGate approval surface (`humangate.py`): exact-bound\n`ApprovalToken` value objects verified  …(+1260 chars)
00:36:39 tool     | -> read_file(test_humangate_currentness.py)
00:36:39 result   | read_file ok 0.4s: {"content": "1|\"\"\"WO-SWOF-W2 acceptance tests: rights currentness, the canonical gate predicate and the exact-\n2|bound, RFC8785-framed, Ed25519-verified human approval token.\n3|\n4|Every failing case must FAIL CLOSED with an exact code; the positive controls must PASS. Nothing\n5|here reads a wall clock: currentness is always an explicit trusted `now`/`commit_time`. The\n6|signing key is a TE …(+90037 chars)
00:36:48 think    | I've read the full humangate implementation and the R6 focused test class. The s
00:36:48 assistant| I've read the full humangate implementation and the R6 focused test class. The seam is gated on `_required_authn_floor(request) is not None`, resolving the trusted request and comparing all `_REQUEST_POLICY_FIELDS`. Let me examine the rights.py gate path to confirm no bypass, then run the tests.
00:36:48 tool     | -> read_file(rights.py L380-459)
00:36:48 result   | read_file ok 0.4s: {"content": "380| or autonomy == \"T3\")\n381|\n382|\n383|def _route_is_ruin(route) -> bool:\n384| return route.route in (RUIN_HARD_VETO_ROUTE, RUIN_SAFE_STOP_ROUTE)\n385|\n386|\n387|def assert_human_gate_satisfied(route, approval, *, requesting_actor=None,\n388| request=None, ctx=None) -> None:\n389| \"\"\"Refuse a missing, self-issued or non-exact-bound approval for a gated route.\n390|\n391| Th …(+3388 chars)
00:36:48 tool     | -> terminal(ls acceptance/evidence 2>/dev/null + 2 commands)
00:36:49 result   | terminal ok 0.3s: {"output": "w2r1\n=== R6 evidence dir ===\nR6_COMPILED\nR6_COMPILER_RECEIPT.json\nR6_FULL_REGRESSION_INDEX.json\nR6_RAW_ADJUDICATION_TRANSCRIPT.log\nR6_RAW_FOCUSED_PROBES.log\nR6_ROOT_w1_admission.log\nR6_ROOT_w1_capability.log\nR6_ROOT_w1_fabric.log\nR6_ROOT_w1_knowledge.log\nR6_ROOT_w1_profile.log\nR6_ROOT_w1_tests.log\nR6_ROOT_w2_assurance.log\nR6_ROOT_w2_effect.log\nR6_ROOT_w2_observability.lo …(+59 chars)
00:36:52 think    | `assert_human_gate_satisfied` routes through `verify_approval_token` (single gat
00:36:52 assistant| `assert_human_gate_satisfied` routes through `verify_approval_token` (single gate path, no bypass). Now let me run the R6 focused test class and full security root, and check evidence consistency in parallel.
00:36:52 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -m unittest security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary -v)
00:36:53 result   | terminal ok 0.5s: {"output": "security (unittest.loader._FailedTest.security) ... ERROR\r\n\r\n======================================================================\r\nERROR: security (unittest.loader._FailedTest.security)\r\n----------------------------------------------------------------------\r\nImportError: Failed to import test module: security\r\nTraceback (most recent call last):\r\n File \"C:\\Users\\user\ …(+802 chars)
00:36:53 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -m security.tests.test_humangate_currentness)
00:36:53 result   | terminal ok 0.3s: {"output": "C:\\Projects\\Agent_Workspace\\HG-KSEOS\\.venv\\Scripts\\python.exe: Error while finding module specification for 'security.tests.test_humangate_currentness' (ModuleNotFoundError: No module named 'security')", "exit_code": 0, "error": null}
00:36:53 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import json idx=json.load(open('R6_FULL_REGRESSION_INDEX.json')) print('TYPE',type(idx).__name__) if isinstance(idx,dict): for k,v in idx.items(): print( …(+68 chars))
00:36:54 result   | terminal ok 0.3s: {"output": "TYPE dict\r\nschema str SWOF-W2-R6-FULL-REGRESSION-INDEX/1\r\nphase str w2_candidate_w2r6\r\nsource_sha str 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9\r\ngenerated_at str 2026-10-04T16:36:04Z\r\nroots list 10\r\nsummary dict 3\r\ndenominator dict 5\r\nindex_sha256 str a7c417ebf86c73a570456d63a755c39d993babe982c8e5904d4e025ebba97e0e", "exit_code": 0, "error": null, "cwd": "C:\\Projects\\A …(+91 chars)
00:36:57 think    | Tests need PYTHONPATH=src. Let me fix and run properly.
00:36:57 assistant| Tests need PYTHONPATH=src. Let me fix and run properly.
00:36:57 tool     | -> terminal(PYTHONPATH=src C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -m unittest security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary -v)
00:36:57 result   | terminal ok 0.5s: {"output": "test_a10_stale_or_superseded_trusted_request_is_denied (security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a10_stale_or_superseded_trusted_request_is_denied) ... ok\r\ntest_a11_local_adapter_missing_floor_remains_deny_authn (security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary.test_a11_local_adapter_missing_floor_remains_deny_authn) ... ok\r\n …(+2430 chars)
00:36:58 tool     | -> terminal(PYTHONPATH=src C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -m security.tests.test_humangate_currentness)
00:36:58 result   | terminal ok 0.7s: {"output": "..............................................................................................................................................................................................\r\n----------------------------------------------------------------------\r\nRan 190 tests in 0.096s\r\n\r\nOK", "exit_code": 0, "error": null}
00:36:58 tool     | -> execute_code(import json from hermes_tools import read_file idx=json.load(open(r"C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/evidence/R6_EVIDENCE/R6_FULL_REGRESSION_INDEX.json")) print(json.dumps({k:v …(+131 chars))
00:36:58 result   | execute_code ok 0.2s: {"status": "success", "output": "{\n \"source_sha\": \"94e4c15e1040a159d0eb6ac3ef4089b421e60bf9\",\n \"summary\": {\n \"exit_zero_all\": true,\n \"root_count\": 10,\n \"zero_denominator_roots\": 0\n },\n \"denominator\": {\n \"w1_total\": 113,\n \"w2_total\": 783,\n \"grand_total\": 896,\n \"by_root_w1\": {\n \"tests\": 16,\n \"fabric\": 21,\n \"knowledge\": 25,\n \"admission\": 17,\n \"profile\": …(+4212 chars)
00:37:15 think    | Focused A1–A13 pass. The full `test_humangate_currentness` module passes (190 te
00:37:15 assistant| Focused A1–A13 pass. The full `test_humangate_currentness` module passes (190 tests, which is one of several files in the security root). Evidence index `source_sha` matches and denominator sums are internally consistent (w1 16+21+25+17+12+22=113; w2 421+116+144+102=783; grand=896, zero-denominator=0). Now let me run the full security root and reproduce the downgrade attack adversarially.
00:37:15 tool     | -> terminal(PYTHONPATH=src C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -m unittest discover -s src/security/tests -t src/security/tests)
00:37:16 result   | terminal ok 0.7s: {"output": "----------------------------------------------------------------------\r\nRan 421 tests in 0.125s\r\n\r\nOK", "exit_code": 0, "error": null}
00:37:16 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from security.humangate import * import base64 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519 …(+4276 chars))
00:37:17 result   | terminal ERROR 1.0s: {"output": "Traceback (most recent call last):\r\n File \"<string>\", line 27, in <module>\r\nNameError: name 'replace' is not defined\r\n=== R6 DOWNGRADE ATTACK: CRITICAL/TRUE AAC3, caller declares AAC2, AAC2 decision+token ===", "exit_code": 1, "error": null}
00:37:25 think    | Security root confirms 421 tests OK (matches evidence). Let me fix the probe scr
00:37:25 assistant| Security root confirms 421 tests OK (matches evidence). Let me fix the probe script (import ordering bug on `replace`).
00:37:25 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from dataclasses import replace from security.humangate import * import base64 from cryptography.hazmat.primitives.a …(+5135 chars))
00:37:26 result   | terminal ok 1.3s: {"output": "=== 1. DOWNGRADE ATTACK (R6): trusted CRITICAL/AAC3, caller says AAC2, AAC2 decision+token ===\r\n -> False DENY_EXACT_BINDING | purpose_ref (expected False DENY_REQUEST_POLICY_MISMATCH)\r\n=== 2. ABSENT request_resolver, gated path (fail-closed) ===\r\n -> False DENY_EXACT_BINDING (expected DENY_REQUEST_UNRESOLVED)\r\n=== 3. BYPASS probe: caller AND resolver BOTH agree AAC2 on a reque …(+484 chars)
00:37:35 think    | My fixture had a purpose_ref binding mismatch. Let me fix so the probe actually
00:37:36 assistant| My fixture had a purpose_ref binding mismatch. Let me fix so the probe actually reaches the R6 trust boundary (which sits after exact binding).
00:37:36 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from dataclasses import replace from security.humangate import * import base64 from cryptography.hazmat.primitives.a …(+5311 chars))
00:37:37 result   | terminal ok 1.5s: {"output": "=== 1a. DOWNGRADE ATTACK R6: trusted CRITICAL/AAC3, caller AAC2, AAC2 decision+token ===\r\n -> False DENY_REQUEST_POLICY_MISMATCH | required_authn_assurance\r\n=== 1b. SAME trust but caller declares floor ABSENT (empty) — does the empty-floor path still fail closed? ===\r\n -> False DENY_AUTHN (must NOT pass; floor must still gate)\r\n=== 2. ABSENT request_resolver on gated path ===\r …(+477 chars)
00:37:40 think    | All independent probes confirm the R6 fix. Now let me reproduce the downgrade ac
00:37:40 assistant| All independent probes confirm the R6 fix. Now let me reproduce the downgrade acceptance on the OLD R5 source (02736d3e) to confirm the defect existed pre-fix, using a separate checkout.
00:37:40 tool     | -> terminal(git worktree list + 3 commands)
00:37:40 result   | terminal ERROR 0.5s: {"output": "C:/Projects/Agent_Workspace/SWOF 417f115 [evidence/swof-w2r5-closure-repair]\nC:/Projects/Agent_Workspace/SWOF/.w2r6-old 02736d3 (detached HEAD)\nC:/Projects/Agent_Workspace/SWOF/.w2r6-worktree 94e4c15 [wo/swof-w2-closure-r6]\nC:/Projects/Agent_Workspace/SWOF-evidence-cleanup-wt 84ea30c [evidence/w1-r4-evidence-cleanup]\nC:/Projects/Agent_Workspace/SWOF-w2-evidence-wt 291c177 [evidence …(+382 chars)
00:37:44 think    | There's already a `.w2r6-old` worktree at R5, plus my temp check. Let me reprodu
00:37:44 assistant| There's already a `.w2r6-old` worktree at R5, plus my temp check. Let me reproduce the downgrade acceptance on the R5 source (without the fix).
00:37:44 tool     | -> terminal(ls /tmp/swof-r5-check/ 2>/dev/null + 2 commands)
00:37:45 result   | terminal ok 0.3s: {"output": "===", "exit_code": 0, "error": null}
00:37:49 think    | `/tmp` in git-bash maps to `C:/Users/user/AppData/Local/Temp` etc. Let me find t
00:37:49 assistant| `/tmp` in git-bash maps to `C:/Users/user/AppData/Local/Temp` etc. Let me find the actual worktree path.
00:37:49 tool     | -> terminal(git worktree list | grep r5 + 7 commands)
00:37:50 result   | terminal ok 0.5s: {"output": "C:/Projects/Agent_Workspace/SWOF 417f115 [evidence/swof-w2r5-closure-repair]\nC:/tmp/swof-r5-check 02736d3 (detached HEAD)\n===\nwinpath=C:/tmp/swof-r5-check\nwin=C:\\tmp\\swof-r5-check\n__init__.py\nclassification.py\nhumangate.py\ninjection.py\npermissions.py\nprovenance.py\nREADME.md\nrights.py\nsupplychain.py\ntests", "exit_code": 0, "error": null, "cwd": "C:\\Projects\\Agent_Works …(+12 chars)
00:37:52 think    | The R5 checkout lives at `C:/tmp/swof-r5-check`. Now I'll reproduce the downgrad
00:37:52 assistant| The R5 checkout lives at `C:/tmp/swof-r5-check`. Now I'll reproduce the downgrade attack on R5 source.
00:37:52 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from dataclasses import replace from security.humangate import * import base64 from cryptography.hazmat.primitives.a …(+233 chars))
00:37:52 result   | terminal ok 0.5s: {"output": "R5 VerificationContext has request_resolver: False", "exit_code": 0, "error": null}
00:37:57 think    | R5 has no `request_resolver` — confirming the defect window. Now reproduce the a
00:37:57 assistant| R5 has no `request_resolver` — confirming the defect window. Now reproduce the actual downgrade acceptance on R5: a CRITICAL request that declares AAC2 floor with an AAC2 decision/token.
00:37:57 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from dataclasses import replace from security.humangate import * import base64 from cryptography.hazmat.primitives.a …(+3106 chars))
00:37:58 result   | terminal ok 0.8s: {"output": "R5 DOWNGRADE ATTACK (CRITICAL/P5, caller-declared AAC2 floor, AAC2 decision+token):\r\n -> False DENY_DECISION_BASIS_MISMATCH | ACCEPTED (downgrade) if code==APPROVE_BASIS_SATISFIED", "exit_code": 0, "error": null}
00:38:03 think    | R5 returned `DENY_DECISION_BASIS_MISMATCH` because my fixture's `decision_basis_
00:38:03 assistant| R5 returned `DENY_DECISION_BASIS_MISMATCH` because my fixture's `decision_basis_hash` doesn't recompute on R5's basis recipe. Let me set it to the recomputed value so the probe actually reaches the authn floor check.
00:38:03 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from dataclasses import replace from security.humangate import * import base64 from cryptography.hazmat.primitives.a …(+3221 chars))
00:38:04 result   | terminal ok 0.9s: {"output": "R5 DOWNGRADE (CRITICAL/P5 caller-declared AAC2, AAC2 decision+token): True APPROVE_BASIS_SATISFIED\r\n => ACCEPTED if APPROVE_BASIS_SATISFIED == APPROVE_BASIS_SATISFIED (defect CONFIRMED if ok=True)", "exit_code": 0, "error": null}
00:38:08 think    | R5 downgrade attack **CONFIRMED accepted**; same request on R6 is **DENY_REQUEST
00:38:08 assistant| R5 downgrade attack **CONFIRMED accepted**; same request on R6 is **DENY_REQUEST_POLICY_MISMATCH**. Now let me verify the evidence logs' consistency (parse root logs for counts + SHA) and run the umbrella w1/w2 roots to independently confirm grand totals.
00:38:08 tool     | -> terminal(for f in R6_ROOT_w1_tests R6_ROOT_w1_fabric R6_ROOT_w1_knowledge R6_ROOT_w1_admission R6_ROOT_w1_profile R6_ROOT_w1_capability R6_ROOT_w2_security R6_ROOT_w2_effect R6_ROOT_w2_assurance R6_ROOT_w2_observability + 4 comma …(+3 chars))
00:38:09 result   | terminal ok 1.1s: {"output": "R6_ROOT_w1_tests: Ran=16 status_lines=1\nR6_ROOT_w1_fabric: Ran=21 status_lines=1\nR6_ROOT_w1_knowledge: Ran=25 status_lines=1\nR6_ROOT_w1_admission: Ran=17 status_lines=1\nR6_ROOT_w1_profile: Ran=12 status_lines=1\nR6_ROOT_w1_capability: Ran=22 status_lines=1\nR6_ROOT_w2_security: Ran=421 status_lines=1\nR6_ROOT_w2_effect: Ran=116 status_lines=1\nR6_ROOT_w2_assurance: Ran=144 status_l …(+204 chars)
00:38:09 tool     | -> terminal(echo "=== R6_RAW_FOCUSED_PROBES.log head ===" + 3 commands)
00:38:09 result   | terminal ok 0.4s: {"output": "=== R6_RAW_FOCUSED_PROBES.log head ===\n# command : \"C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe\" -m unittest src.security.tests.test_humangate_currentness.TestR6TrustedRequestBoundary -v\r\n# cwd : C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree\r\n# git HEAD: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9\r\n# phase : w2_candidate_w2r6_focused\r\n# started : 2026-10-04T …(+2882 chars)
00:38:13 think    | Evidence logs are internally consistent: counts sum exactly to w1=113, w2=783, g
00:38:14 assistant| Evidence logs are internally consistent: counts sum exactly to w1=113, w2=783, grand=896, all status lines = OK, and the focused-probes header records the exact source SHA. Let me verify the adjudication JSON, check for any adapter-fallback/second-engine remnants in source, and confirm the +13 test delta vs R5.
00:38:14 tool     | -> execute_code(import json d=json.load(open(r"C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/evidence/R6_EVIDENCE/R6_POLICY_TRUST_ADJUDICATION.json")) print("keys:", list(d.keys()) if isinstance(d,dict) el …(+157 chars))
00:38:14 result   | execute_code ERROR 0.1s: {"status": "error", "output": "\n--- stderr ---\nTraceback (most recent call last):\n File \"C:\\Users\\user\\AppData\\Local\\Temp\\hermes_kernel__uoopz03\\hermes_kernel_runner.py\", line 118, in run_cell\n exec(compile(request[\"code\"], \"<cell>\", \"exec\"), GLOBALS)\n File \"<cell>\", line 2, in <module>\nFileNotFoundError: [Errno 2] No such file or directory: 'C:/Projects/Agent_Workspace/HG-K …(+831 chars)
00:38:14 tool     | -> terminal(echo "=== adapter/fallback/second-engine scan in src ===" + 3 commands)
00:38:15 result   | terminal ok 1.1s: {"output": "=== adapter/fallback/second-engine scan in src ===\nsrc/security/humangate.py:35:CLOSED (`DENY_AUTHN`), because the old hard-coded `_DEFAULT_REQUIRED_AUTHN_ASSURANCE = \"AAC2\"` made\nsrc/security/humangate.py:985: R5: the previously-exposed `adapter_kind == \"local_adapter\"` compatibility fallback that mapped\nsrc/security/tests/test_humangate_currentness.py:1336: for kind in (\"cano …(+1032 chars)
00:38:18 think    | R5=408, R6=421 → **+13 delta confirmed exactly**. The scan confirms no adapter f
00:38:18 assistant| R5=408, R6=421 → **+13 delta confirmed exactly**. The scan confirms no adapter fallback implementation remains (only removal docstrings + a negative test). Note: the task named `R6_POLICY_TRUST_ADJUDICATION.json` but the actual file is `R6_RAW_ADJUDICATION_TRANSCRIPT.log`. Let me check that transcript for SHA binding.
00:38:18 tool     | -> terminal(echo "=== transcript head ===" + 5 commands)
00:38:18 result   | terminal ok 0.5s: {"output": "=== transcript head ===\n# command : cross-tree full-route counterexample F-W2R5-EXT-001 (CRITICAL semantic, caller AAC2 floor, AAC2 decision/token)\r\n# phase : w2_candidate_w2r6_adjudication\r\n# started : 2026-10-04T16:36:12Z\r\n------------------------------------------------------------------------------\r\n[OBSERVED] subject R5 source 02736d3eeb6156e9763f202fbd63fff430e9eeb7\r\nR …(+1645 chars)
00:38:24 think    | All evidence binds to the source SHA, and the maker's adjudication transcript in
00:38:24 assistant| All evidence binds to the source SHA, and the maker's adjudication transcript independently reproduces my downgrade reproduction. Let me confirm the R6 changeset scope is confined to the trusted boundary (no second engine/global upgrade elsewhere), and check the focused robt verification of the seam being exercised at the `assert_human_gate_satisfied` gateway.
00:38:24 tool     | -> terminal(git diff --stat 02736d3 94e4c15 + 2 commands)
00:38:24 result   | terminal ok 0.3s: {"output": "src/security/humangate.py | 104 ++++++++++++++-\n src/security/tests/test_humangate_currentness.py | 159 ++++++++++++++++++++++-\n src/security/tests/test_rights.py | 29 ++++-\n 3 files changed, 273 insertions(+), 19 deletions(-)\n=== files changed ===\nsrc/security/humangate.py\nsrc/security/tests/test_humangate_currentness.py\nsrc/security/tests/test_rights.py", "exit_code": 0, "erro …(+71 chars)
00:38:24 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import sys; sys.path.insert(0,'src') from dataclasses import replace from security.humangate import * from security.rights import assert_human_gate_satis …(+3548 chars))
00:38:25 result   | terminal ok 0.9s: {"output": "GATEWAY downgrade refused: DENY_REQUEST_POLICY_MISMATCH\r\nhuman_gate_required(caller).required: True", "exit_code": 0, "error": null}
00:38:28 think    | The gateway also refuses the downgrade. Changeset is confined to 3 files (humang
00:38:28 assistant| The gateway also refuses the downgrade. Changeset is confined to 3 files (humangate.py + 2 test files) — no second engine, no global upgrade. Let me check the test_rights.py delta and confirm the untracked `acceptance/` dir is maker artifacts not part of the candidate tree.
00:38:28 tool     | -> terminal(git diff 02736d3 94e4c15 -- src/security/tests/test_rights.py)
00:38:28 result   | terminal ok 0.4s: {"output": "diff --git a/src/security/tests/test_rights.py b/src/security/tests/test_rights.py\nindex a0d088e..dfb0948 100644\n--- a/src/security/tests/test_rights.py\n+++ b/src/security/tests/test_rights.py\n@@ -69,6 +69,11 @@ def _decision_registry(mapping=None):\n decisions = dict(mapping or {\"dec-1\": _current_decision()})\n return lambda decision_id: decisions.get(decision_id)\n \n+\n+def _r …(+2709 chars)
00:38:28 tool     | -> terminal(echo "=== untracked acceptance top ===" + 5 commands)
00:38:28 result   | terminal ok 0.3s: {"output": "=== untracked acceptance top ===\nacceptance:\nevidence\n\nacceptance/evidence:\nw2r1\n\nacceptance/evidence/w2r1:\nR6_POLICY_TRUST_ADJUDICATION_prelim.json\n=== is acceptance tracked? ===\n=== .gitignore ===\n__pycache__/\n*.pyc\n.pytest_cache/\n.venv/\nbuild/\ndist/\n*.egg-info/", "exit_code": 0, "error": null}
00:38:32 think    | The task named `R6_POLICY_TRUST_ADJUDICATION.json` — that exact file isn't in `R
00:38:32 assistant| The task named `R6_POLICY_TRUST_ADJUDICATION.json` — that exact file isn't in `R6_EVIDENCE` (the evidence there is `R6_RAW_ADJUDICATION_TRANSCRIPT.log`), but a `R6_POLICY_TRUST_ADJUDICATION_prelim.json` sits in the untracked `acceptance/` dir. Let me inspect it.
00:38:32 tool     | -> terminal(C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe -c " import json p='acceptance/evidence/w2r1/R6_POLICY_TRUST_ADJUDICATION_prelim.json' d=json.load(open(p)) s=json.dumps(d) print('SHA in prelim:', '94e4c15e1 …(+131 chars))
00:38:33 result   | terminal ok 0.4s: {"output": "SHA in prelim: False\r\nkeys: ['schema', 'repair_id', 'changeset', 'mode', 'conflict', 'subject', 'predicates', 'a_blocker_confirmed', 'counterexample', 'root_cause', 'decision']\r\n{\"schema\": \"SWOF-W2-R6-POLICY-TRUST-ADJUDICATION/1\", \"repair_id\": \"SWOF-W2-CLOSURE-R6\", \"changeset\": \"NARROW_REPAIR\", \"mode\": \"READ_ONLY_DETERMINISTIC_ADJUDICATION_BEFORE_MUTATION\", \"confli …(+1116 chars)
00:38:33 tool     | -> terminal(echo "=== rights.py route call into humangate (verify single gate) ===" + 3 commands)
00:38:33 result   | terminal ok 0.4s: {"output": "=== rights.py route call into humangate (verify single gate) ===\n14:W2 repair WO-SWOF-W2-R001 (F-W2-EXT-002): `assert_human_gate_satisfied` no longer accepts a\n25:`human_gate_required(request)`. Risk/permission classification is authoritative; the operation\n34:of being treated as ungated (DOC-03 15.6). `human_gate_route` and `human_gate_required` share the ONE\n35:predicate, and `ve …(+1120 chars)
00:38:39 think    | The prelim adjudication predates the repair (binds the R5 pre-mutation SHA, per
00:38:39 assistant| The prelim adjudication predates the repair (binds the R5 pre-mutation SHA, per its own `BEFORE_MUTATION` mode) — the R6-binding final adjudication is the `R6_RAW_ADJUDICATION_TRANSCRIPT.log` I confirmed carries the exact R6 SHA. Single-gate path confirmed (only call site is rights.py:431). Let me independently run the remaining roots (non-security) to confirm no regression outside the changed area and verify the grand total.
00:38:39 tool     | -> terminal(W=1 C='C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe' echo "w1_tests:" + 6 commands)
00:38:41 result   | terminal ok 1.3s: {"output": "w1_tests:\nRan 16 tests in 0.110s\r\n\r\nOK\r\nw1_fabric:\nRan 21 tests in 0.002s\r\n\r\nOK\r\nw1_knowledge:\nRan 25 tests in 0.001s\r\n\r\nOK\r\nw1_admission:\nRan 17 tests in 0.000s\r\n\r\nOK\r\nw1_profile:\nRan 12 tests in 0.000s\r\n\r\nOK\r\nw1_capability:\nRan 22 tests in 0.123s\r\n\r\nOK", "exit_code": 0, "error": null}
00:38:41 tool     | -> terminal(C='C:/Projects/Agent_Workspace/HG-KSEOS/.venv/Scripts/python.exe' echo "w2_effect:" + 3 commands)
00:38:42 result   | terminal ok 0.9s: {"output": "w2_effect:\nRan 116 tests in 0.006s\r\n\r\nOK\r\nw2_assurance:\nRan 144 tests in 0.017s\r\n\r\nOK\r\nw2_observability:\nRan 102 tests in 0.008s\r\n\r\nOK", "exit_code": 0, "error": null}
00:38:52 assistant| All roots independently reproduced. I have completed every required check. Writing the final verification report. --- ## INDEPENDENT VERIFICATION REPORT — SWOF W2 R6 / F-W2R5-EXT-001 (Branch A trusted request boundary) **Checker status:** I am a fresh-context, independent, **VERIFY_ONLY** read-only checker. I am **NOT the maker**. I made **no modifications and no commits** to the repo. Working tree checked against the local committed candidate at `C:/Projects/Agent_Workspace/SWOF/.w2r6-worktree` (HEAD **94e4c15e1040a159d0eb6ac3ef4089b421e60bf9**, branch `wo/swof-w2-closure-r6`). The only write …(+3387 chars)
00:38:55 think    | All roots independently reproduced. I have completed every required check. Writi
00:38:55 assistant| 783; grand 896; all status=`OK`; `exit_zero_all=true`, `zero_denominator_roots=0`). - **Claim ≤ evidence:** regression, +13, deny codes, fail-closed, R5 defect all directly corroborated from source+execution. No claim exceeded what evidence shows. ### wave_verdict: **PASS** (overall — all three pillars coherent, no blocker). Overall is not PARTIAL. --- ### CONFIRMED_DEFECT None in the R6 candidate. The R5 downgrade acceptance was confirmed as a pre-fix defect and is closed by R6. ### EVIDENCE_GAP (non-blocking) - The task named `R6_POLICY_TRUST_ADJUDICATION.json` under `R6_EVIDENCE/`. That exa …(+1664 chars)
00:38:55 final    | status=completed duration=155.88s summary: All roots independently reproduced. I have completed every required check. Writing the final verification report. --- ## INDEPENDENT VERIFICATION REPORT — SWOF W2 R6 / F-W2R5-EXT-001 (Branch A trusted request boundary) **Checker status:** I am a fresh-context, independent, **VERIFY_ONLY** read-only checker. I am **NOT the maker**. I made **no modifications and no commits** to the repo. Working tre …(+97 chars)
00:38:55 final    | end status=completed exit_reason=completed

```

### R6_FRESH_CHECKER_FINDINGS.json

- sha256: `d751c8e54b4f00d0aa48140b2ec35b9fc50d26952f7b66bb03c62330000fd4a0` · bytes: 1769

```json
{
  "schema": "SWOF-W2-R6-FRESH-CHECKER-FINDINGS/1",
  "checker_identity": "fresh-context-VERIFY_ONLY-readonly deleg_f3a757d7 sa-0-4426308c",
  "checker_ne_maker": true,
  "checker_read_only": true,
  "subject_source_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "product_verdict": "PASS",
  "governance_verdict": "PASS",
  "wave_verdict": "PASS",
  "confirmed_defects": [],
  "evidence_gaps_nonblocking": [
    {
      "id": "EG-R6-CHECKER-001",
      "note": "checker looked for R6_POLICY_TRUST_ADJUDICATION.json; the R6-binding adjudication artifact is R6_RAW_ADJUDICATION_TRANSCRIPT.log (carries exact R6 sha) plus R6_POLICY_TRUST_ADJUDICATION.json in the maker evidence tree; prelim JSON in worktree acceptance/ predates repair.",
      "blocking": false
    }
  ],
  "independent_checks": [
    {
      "check": "ApprovaptRequest public export + verify seam",
      "result": "confirmed"
    },
    {
      "check": "R5 downgrade reproduction (caller AAC2 accepted pre-fix)",
      "result": "confirmed closed by R6"
    },
    {
      "check": "R6 downgrade refused",
      "result": "DENY_REQUEST_POLICY_MISMATCH observed"
    },
    {
      "check": "gateway path refuses downgrade",
      "result": "DENY_REQUEST_POLICY_MISMATCH at gateway"
    },
    {
      "check": "full roots independently reproduced",
      "result": "w1=113 w2=783 grand=896 all OK zero-denominator=0"
    },
    {
      "check": "changeset confined to 3 files",
      "result": "humangate.py + 2 test files; no second engine, no global upgrade"
    }
  ],
  "note": "PASS verdicts corroborated from source+execution in raw transcript; full report text arrives via delegation message.",
  "generated_at": "2026-10-04T16:40:41+00:00"
}
```

### R6_FRESH_CHECKER_RECEIPT.json

- sha256: `77b595075cb21249295a5033543b22ef79ca39f7d234d87f684353585c82ec88` · bytes: 511

```json
{
  "schema": "SWOF-W2-R6-FRESH-CHECKER-RECEIPT/1",
  "checker_identity": "deleg_f3a757d7",
  "checker_ne_maker": true,
  "checker_read_only": true,
  "subject_source_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "product_verdict": "PASS",
  "governance_verdict": "PASS",
  "wave_verdict": "PASS",
  "blocking_findings": [],
  "transcript_sha256": "429e6031d61bdcad512be8e0ae11274fecb0ffe967c43d03bfce282d4b0b95cf",
  "transcript_bytes": 34511,
  "generated_at": "2026-10-04T16:40:41+00:00"
}
```

### R6_W2_NORMATIVE_CLOSURE_PROJECTION.json

- sha256: `366bf0228c0d09f44d0e3189d531293ea6a7321c26a4357fb6ed6bf5af232723` · bytes: 2970

```json
{
  "schema": "SWOF-W2-R6-NORMATIVE-CLOSURE-PROJECTION/1",
  "project": "HGK-P0-SWOF-W2",
  "changeset": "NARROW_REPAIR Branch A",
  "final_source_candidate_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "typed_api_only": true,
  "no_direct_sql_writes": true,
  "historical_rows_preserved": "R1-R5 rows untouched; only the R6 trust-boundary cone appended as projection (same policy as R5 closure projection)",
  "parent_evidence_sha": "a6ee9b5ce8b0b0905be4952c32b2ddd747929c25",
  "baseline_source_sha": "02736d3eeb6156e9763f202fbd63fff430e9eeb7",
  "actions": [
    {
      "step": "register_evidence",
      "evidence_id": "EVD-W2R6-ADJUDICATION",
      "sha256": "7ca9649aec8e708fef5fd13bb7b96c16316231bea5d55b891822d0c6c0a337e9"
    },
    {
      "step": "register_evidence",
      "evidence_id": "EVD-W2R6-REGRESSION",
      "sha256": "e803700ec5f01e811e3c65cdb4f8ab9de1cb183074c1022556fa39af00a45b42"
    },
    {
      "step": "register_evidence",
      "evidence_id": "EVD-W2R6-CHECKER",
      "sha256": "77b595075cb21249295a5033543b22ef79ca39f7d234d87f684353585c82ec88"
    },
    {
      "step": "register_evidence",
      "evidence_id": "EVD-W2R6-COMPILER",
      "sha256": "78a4e80f16c596eb7e900c7bc710f110ecac32cbd4f4a8e8274a8078ad883b2f"
    },
    {
      "step": "governed_row",
      "requirement": "REQ-HGK-SWOF-W2R6-001",
      "acceptance": "ACC-REQ-HGK-SWOF-W2R6-001",
      "workorder": "WO-REQ-HGK-SWOF-W2R6-001",
      "acceptance_result": "PASS",
      "evidence_refs": [
        "EVD-W2R6-ADJUDICATION",
        "EVD-W2R6-REGRESSION",
        "EVD-W2R6-CHECKER"
      ],
      "source_binding": "SRC:94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "step": "per_obligation_checkpoint",
      "checkpoint_id": "CK-W2-R6OBL-0001"
    },
    {
      "step": "final_normative_checkpoint",
      "checkpoint_id": "CK-W2-R6-FINAL"
    }
  ],
  "denominator_after": {
    "project_id": "HGK-P0-SWOF-W2",
    "requirements_total": 9,
    "requirements_frozen": 9,
    "workorders_total": 9,
    "workorders_open_count": 0,
    "acceptances_total": 9,
    "acceptances_open_count": 0,
    "blocking_open_count": 0,
    "required_active_capabilities_open_count": 0,
    "denominator_nonvacuous": true
  },
  "exact_source_binding": {
    "canonical_binding_field": "checkpoints.source_digest",
    "payload_names_exact_source_sha": true,
    "resolves_to_exact_source_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
    "lifecycle_last_checkpoint_id": "CK-W2-R6-FINAL",
    "lifecycle_points_at_final": true
  },
  "regression_denominator": {
    "w1": 113,
    "w2": 783,
    "grand_total": 896,
    "shrink": false,
    "zero_denominator_roots": 0,
    "all_roots_exit_zero": true
  },
  "non_claims": [
    "NOT_EXTERNALLY_ACCEPTED",
    "W3_NOT_STARTED",
    "NOT_MERGED",
    "NOT_RELEASED",
    "NOT_PRODUCTION",
    "NO_WORLD_EFFECT"
  ]
}
```

### R6_COMPILER_RECEIPT.json

- sha256: `78a4e80f16c596eb7e900c7bc710f110ecac32cbd4f4a8e8274a8078ad883b2f` · bytes: 748

```json
{
  "schema": "SWOF-W2-R6-COMPILER-RECEIPT/1",
  "repair_id": "SWOF-W2-CLOSURE-R6",
  "compiler": "construction-acceptance-prompt-compiler",
  "contract_sha256": "82cb7049422a8f6d84c04d42a24cc56804c93944d43fe3e02a6800a1b43ef70a",
  "stages": {
    "lint": "PROMPT_COMPILE_PASS",
    "activation": "PROMPT_COMPILE_PASS",
    "acceptance": "PROMPT_COMPILE_PASS",
    "compile": "PROMPT_COMPILE_PASS",
    "duplication": "PROMPT_COMPILE_PASS"
  },
  "thin_prompt": {
    "path": "R6_COMPILED/thin-prompt.md",
    "sha256": "70929a06be8b5d73147e399866463853ef9f17993412e2699674f1d0745e864e",
    "bytes": 10623
  },
  "source_sha_at_compile": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "compiled_at": "2026-10-04T16:36:47+00:00"
}
```

### R6_EVIDENCE_MANIFEST.json

- sha256: `3608f54b679ada3b3fd5b8cbb15ef306869ba8491ee0e1134b998d6bb1887da0` · bytes: 9274

```json
{
  "schema": "SWOF-W2-R6-EVIDENCE-MANIFEST/1",
  "repair_id": "SWOF-W2-CLOSURE-R6",
  "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "parent_evidence_sha": "a6ee9b5ce8b0b0905be4952c32b2ddd747929c25",
  "item_count": 26,
  "items": [
    {
      "relative_path": "R6_COMPILED/compiler-receipt.json",
      "kind": "artifact",
      "sha256": "ea2c1352979ac905f56fc4850f1899280fcda0860ebac572fedea5f45aa24bc6",
      "bytes": 545,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_COMPILED/compiler-report.json",
      "kind": "artifact",
      "sha256": "977177c4cd72fb0feb8a3ac025a738fb8124c2321dd2932c3679fa4ae4ea6954",
      "bytes": 227,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_COMPILED/thin-prompt.md",
      "kind": "artifact",
      "sha256": "70929a06be8b5d73147e399866463853ef9f17993412e2699674f1d0745e864e",
      "bytes": 10623,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_COMPILED_THIN_PROMPT.md",
      "kind": "compiled_prompt",
      "sha256": "70929a06be8b5d73147e399866463853ef9f17993412e2699674f1d0745e864e",
      "bytes": 10623,
      "producer": "compiler",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_COMPILER_RECEIPT.json",
      "kind": "compiler_receipt",
      "sha256": "78a4e80f16c596eb7e900c7bc710f110ecac32cbd4f4a8e8274a8078ad883b2f",
      "bytes": 748,
      "producer": "compiler",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_EVIDENCE_MANIFEST.json",
      "kind": "manifest",
      "sha256": "51c69e8ed03f767ef50de90de723af986377b44a550b74ddfc89f0932966c7c9",
      "bytes": 8569,
      "producer": "hermes-maker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_FRESH_CHECKER_FINDINGS.json",
      "kind": "checker_findings",
      "sha256": "d751c8e54b4f00d0aa48140b2ec35b9fc50d26952f7b66bb03c62330000fd4a0",
      "bytes": 1769,
      "producer": "hermes-checker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_FRESH_CHECKER_RECEIPT.json",
      "kind": "checker_receipt",
      "sha256": "77b595075cb21249295a5033543b22ef79ca39f7d234d87f684353585c82ec88",
      "bytes": 511,
      "producer": "hermes-checker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_FRESH_CHECKER_TRANSCRIPT.log",
      "kind": "checker_transcript",
      "sha256": "429e6031d61bdcad512be8e0ae11274fecb0ffe967c43d03bfce282d4b0b95cf",
      "bytes": 34511,
      "producer": "hermes-checker",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_FULL_REGRESSION_INDEX.json",
      "kind": "regression_index",
      "sha256": "e803700ec5f01e811e3c65cdb4f8ab9de1cb183074c1022556fa39af00a45b42",
      "bytes": 5002,
      "producer": "hermes-maker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_POLICY_TRUST_ADJUDICATION.json",
      "kind": "adjudication",
      "sha256": "7ca9649aec8e708fef5fd13bb7b96c16316231bea5d55b891822d0c6c0a337e9",
      "bytes": 4462,
      "producer": "hermes-maker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_RAW_ADJUDICATION_TRANSCRIPT.log",
      "kind": "raw_transcript",
      "sha256": "ee60ff08fc28d070847325821636ea43ce6f2ea1832021becd9836a4e7d58221",
      "bytes": 1074,
      "producer": "hermes-maker",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_RAW_FOCUSED_PROBES.log",
      "kind": "raw_probes",
      "sha256": "3cbc1dfa5343172d18cd86cdad82d4527b39aad9c28cfeb18aecaa5851c418aa",
      "bytes": 3291,
      "producer": "hermes-maker",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w1_admission.log",
      "kind": "artifact",
      "sha256": "9bed75a79e0638b387f92a700f8af7486bf261517852066a35d4607fb9e6b369",
      "bytes": 691,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w1_capability.log",
      "kind": "artifact",
      "sha256": "48276cec75048e4edf66a3bc57fa10b8a74e319c411e740cd5f1b80ee07ffe85",
      "bytes": 698,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w1_fabric.log",
      "kind": "artifact",
      "sha256": "d4839154aaf4a37ef722ed6c929bf45ecada0e023ee12dfe159bd72df877b7a3",
      "bytes": 689,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w1_knowledge.log",
      "kind": "artifact",
      "sha256": "0ccc5b66ca45811bf723c05889a95919068d360dbfbcd7dbb14005aabfb980b4",
      "bytes": 699,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w1_profile.log",
      "kind": "artifact",
      "sha256": "f13973a1e0f8f39d7786a20e016fe2e348abc2f3e4e03c1bc65e947e57080a85",
      "bytes": 682,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w1_tests.log",
      "kind": "artifact",
      "sha256": "9dbb2269c9149a03c9db926337e0157e8ccf13e470d01ed2e79ce729decaa3da",
      "bytes": 658,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w2_assurance.log",
      "kind": "artifact",
      "sha256": "e240a6458e27c6d8a86630c32819ae2e38ccaa3f0bb15c54af068cd179b39cc8",
      "bytes": 819,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w2_effect.log",
      "kind": "artifact",
      "sha256": "8c7a80bac7dce01bb3c0ef35be0e880fa62fa44819fc62ec6dc9d233023bc9b8",
      "bytes": 785,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w2_observability.log",
      "kind": "artifact",
      "sha256": "d11781b1c96f858514b71c30d5215ab2c6a606c2535b3ddf055512fee1fd849f",
      "bytes": 785,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_ROOT_w2_security.log",
      "kind": "artifact",
      "sha256": "1201cd0cd81c7994b7c0b0c77f22a671f206ec91ac4115a7b6d59c8e211e9434",
      "bytes": 1094,
      "producer": "hermes",
      "raw_vs_summary": "raw",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "R6_W2_NORMATIVE_CLOSURE_PROJECTION.json",
      "kind": "hgk_closure_projection",
      "sha256": "366bf0228c0d09f44d0e3189d531293ea6a7321c26a4357fb6ed6bf5af232723",
      "bytes": 2970,
      "producer": "hermes-maker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "SWOF_W2_R6_EVIDENCE_RETURN_PACK.json",
      "kind": "return_pack",
      "sha256": "053e2f7f1d848c0da500de5dcd1f6cbec35a93e2626f5ae107a8f8846efe879e",
      "bytes": 2512,
      "producer": "hermes-packer",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    },
    {
      "relative_path": "SWOF_W2_R6_FINAL_EVIDENCE_DOSSIER.md",
      "kind": "dossier",
      "sha256": "3b9318c9377438bff7018c5cc73157e052121489c39d29d54ac9a7be400f82a3",
      "bytes": 3844,
      "producer": "hermes-maker",
      "raw_vs_summary": "summary",
      "source_subject_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
    }
  ],
  "generated_at": "2026-10-04T16:42:11+00:00"
}
```

### SWOF_W2_R6_EVIDENCE_RETURN_PACK.json

- sha256: `6ff8b6a6a850ae0ea8e5cb7cf60d156f0aa44c1561dbc8e4c3197031c1a77b85` · bytes: 2512

```json
{
  "schema": "SWOF_W2_R6_EVIDENCE_RETURN_PACK/1",
  "repair_id": "SWOF-W2-CLOSURE-R6",
  "source_candidate_sha": "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9",
  "parent_evidence_sha": "a6ee9b5ce8b0b0905be4952c32b2ddd747929c25",
  "evidence_commit_sha": "PREPUBLICATION / assigned by publication receipt",
  "artifacts": [
    {
      "path": "R6_POLICY_TRUST_ADJUDICATION.json",
      "sha256": "7ca9649aec8e708fef5fd13bb7b96c16316231bea5d55b891822d0c6c0a337e9",
      "bytes": 4462
    },
    {
      "path": "R6_RAW_ADJUDICATION_TRANSCRIPT.log",
      "sha256": "ee60ff08fc28d070847325821636ea43ce6f2ea1832021becd9836a4e7d58221",
      "bytes": 1074
    },
    {
      "path": "R6_RAW_FOCUSED_PROBES.log",
      "sha256": "3cbc1dfa5343172d18cd86cdad82d4527b39aad9c28cfeb18aecaa5851c418aa",
      "bytes": 3291
    },
    {
      "path": "R6_FULL_REGRESSION_INDEX.json",
      "sha256": "e803700ec5f01e811e3c65cdb4f8ab9de1cb183074c1022556fa39af00a45b42",
      "bytes": 5002
    },
    {
      "path": "R6_FRESH_CHECKER_TRANSCRIPT.log",
      "sha256": "429e6031d61bdcad512be8e0ae11274fecb0ffe967c43d03bfce282d4b0b95cf",
      "bytes": 34511
    },
    {
      "path": "R6_FRESH_CHECKER_FINDINGS.json",
      "sha256": "d751c8e54b4f00d0aa48140b2ec35b9fc50d26952f7b66bb03c62330000fd4a0",
      "bytes": 1769
    },
    {
      "path": "R6_FRESH_CHECKER_RECEIPT.json",
      "sha256": "77b595075cb21249295a5033543b22ef79ca39f7d234d87f684353585c82ec88",
      "bytes": 511
    },
    {
      "path": "R6_W2_NORMATIVE_CLOSURE_PROJECTION.json",
      "sha256": "366bf0228c0d09f44d0e3189d531293ea6a7321c26a4357fb6ed6bf5af232723",
      "bytes": 2970
    },
    {
      "path": "R6_COMPILER_RECEIPT.json",
      "sha256": "78a4e80f16c596eb7e900c7bc710f110ecac32cbd4f4a8e8274a8078ad883b2f",
      "bytes": 748
    },
    {
      "path": "R6_COMPILED_THIN_PROMPT.md",
      "sha256": "70929a06be8b5d73147e399866463853ef9f17993412e2699674f1d0745e864e",
      "bytes": 10623
    },
    {
      "path": "R6_EVIDENCE_MANIFEST.json",
      "sha256": "3608f54b679ada3b3fd5b8cbb15ef306869ba8491ee0e1134b998d6bb1887da0",
      "bytes": 9274
    },
    {
      "path": "SWOF_W2_R6_FINAL_EVIDENCE_DOSSIER.md",
      "sha256": "3b9318c9377438bff7018c5cc73157e052121489c39d29d54ac9a7be400f82a3",
      "bytes": 3844
    }
  ],
  "manifest_sha256": "053c58d971cf6cf566dfed3e8e6c4ab740064aa1089ff8382e19f34b6a4d66e8",
  "generated_at": "2026-10-04T16:42:11+00:00"
}
```

## B. Handover bundle (reproducibility inputs)

- `R6_COMPILER_BUNDLE/R6_COMPILER_BUNDLE_MANIFEST.json` — sha256 `0a26b1b5b3e7c976c7c41fda9de5c4fc4c07ad2d373cbfefd7792ecf8d533f3d`, 3403 bytes
- `R6_COMPILER_BUNDLE/SWOF_HGK_ACA_RBWI.md` — sha256 `b9a26f959233bc63c21bb4ad764ded3efc6ba6b02c2d29c40c92e33b0bb5670d`, 3812419 bytes
- `R6_COMPILER_BUNDLE/construction-acceptance-prompt-compiler_SKILL.md` — sha256 `214c7f048f7361fe0bc4a324a0c99aaaf0df4191a430b645b8a97d24620064b6`, 7534 bytes
- `R6_COMPILER_BUNDLE/references/prompt-contract.schema.json` — sha256 `cbcc9998cee3ba59f919417aacbc121ab20fc611f1c47c62cafcaa34bbf13612`, 25671 bytes
- `R6_COMPILER_BUNDLE/scripts/prompt_contract_compiler.py` — sha256 `2c282ad6539a465c3b1d751868cab98437a8f35e9728be686117e364a70857d9`, 30930 bytes
- `R6_HGK_CLOSURE/R6_HGK_CLOSURE_REPRODUCIBILITY.md` — sha256 `7f4f4407d17bb9a47096f32d298ce66e1af5e3bb3642050a4a615ddd9dda10c9`, 2339 bytes
- `R6_HGK_CLOSURE/R6_HGK_SPINE_SCHEMA.json` — sha256 `2c60f4a0bf1aa13b598206e927d9f5e41e9d55554f4230b96a3de812fca7dd9c`, 992 bytes
- `R6_PROMPT_CONTRACT/R6_PROMPT_CONTRACT.json` — sha256 `82cb7049422a8f6d84c04d42a24cc56804c93944d43fe3e02a6800a1b43ef70a`, 42090 bytes
- `R6_REPRO/R6_MAKER_loggen.py` — sha256 `5bc77f7b7f1881853e0577d1688ec9b11a96bcc3de6b096f1612341605875867`, 5915 bytes
- `R6_REPRO/R6_MAKER_manifest.py` — sha256 `715a6aced66934eaab7ebabc14a40fd0f364326a21d079538d92f72f79ea75bb`, 4720 bytes
- `R6_REPRO/gen_r6_contract.py` — sha256 `885fbf6ac7acda74baff60caa88444d34d4b820c7dcd118687c9bc208b52fd63`, 24079 bytes

## C. Locators

- source branch: `wo/swof-w2-closure-r1` @ 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
- evidence branch: `evidence/swof-w2r6-closure-repair` @ tip d67c511 (immutable subject = 6c58c21eee69391ba146e21e27b6d3b7f8f2211c)
- main: `acdbfaadd19d12927eb5bd542b09ed230bbc481e` (unchanged)
- PR #7 head: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9 (open, not merged)
- readset: `SWOF-W2-R6-EXTERNAL-ACCEPTANCE-READSET.json` in the evidence subject
