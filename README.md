# SWOF / SWOF GENIE

Greenfield construction root for the SWOF / SWOF GENIE system, built under the HG-KSEOS
governance control plane from the frozen pre-construction baseline.

Baseline locator (external acceptance evidence, outside this repository):

```text
order            SWOF-PRECONSTRUCTION-001
external verdict PASS / PRECONSTRUCTION_EXTERNAL_ACCEPTANCE_GRANTED
closure receipt  HG-KSEOS/evidence/swof-construction-002/closure/
                 SWOF_PRECONSTRUCTION_EXTERNAL_PASS_CLOSURE_RECEIPT.json
receipt sha256   2e9a7c9d2a59aba6af0a9fee0932a973e5fc58b8103e210effffae627111d03a
accepted ZIP     3b18c4e6...445c1 (25,605,869 bytes, 36 members)
```

That acceptance covers the **pre-construction baseline only**. It does not accept this
repository.

---

# 1. 任務執行交接報告 (Task Execution Handoff Report)

> **Audience:** the next HG-KSEOS session that will continue W2 onwards.
> **Purpose:** carry over task memory, hard-won experience, exact state, and the next
> admissible work — without re-deriving any of it.

## 1.1 Where things stand — exact identities

| Item | Value |
|---|---|
| Order | `SWOF-CONSTRUCTION-002` (wave W1, `NARROW_REPAIR` rounds R1–R4) |
| Current local HEAD | `7e1f912d863b8c155eb9ae5ae9682b0e185450fc` |
| Candidate branch | `repair/w1-r4-binding-order-proof` |
| Clean repair baseline | `be036588bdf2d509c929aba9bc2bf0525674bb7a` |
| Reviewed R2 semantic donor | `8689e583bab5198be11fb31442f5ac95d8490c00` |
| Evidence branch | `evidence/w1-r4-binding-order-proof` @ `206ab073e92541cbb0d2acab8a3beebbcfe8c9e9` |
| PR (open draft, DO NOT MERGE) | `#4` — head == `7e1f912d…` |
| Prior PRs left intact | `#2` (`8689e583…`), `#3` (`ed28b784…`) |
| External acceptance | `PENDING_READ_ONLY_EXTERNAL_ACCEPTANCE` |

**Claim level:** `W1_R4_LOCAL_REPAIR_CANDIDATE_WITH_AUTHORITATIVE_PRE_MUTATION_BINDING_MONOTONIC_ORDERING_AND_SUBJECT_BOUND_EVIDENCE`.
This is a **local + independently verified** claim. It is **NOT** external acceptance.

## 1.2 Status

**W0 and W1 complete locally**, with W1 carried through four externally-challenged repair
rounds. **W2–W5 are `PLANNED_NOT_DISPATCHED`.**

| Wave | Scope | State |
|---|---|---|
| W0 | constitution, repo foundation, PD04 packet factory | IMPLEMENTED + INDEPENDENTLY VERIFIED |
| W1 | `src/fabric`, `src/knowledge`, `src/admission`, `src/profile`, `src/capability` | IMPLEMENTED + INDEPENDENTLY VERIFIED (4 repair rounds) |
| W2–W5 | security/assurance, product surfaces, ops/research, migration/handoff | PLANNED_NOT_DISPATCHED |

**This is a W1-stage snapshot with a REDUCED claim.** NOT externally accepted, NOT
released, NOT production. External acceptance of W0–W5 as a whole has not been performed.

## 1.3 The W1 repair history — what each round failed on, and how it closed

Read this before touching W1 again. Each round failed for a *different reason*, and the
reasons are the reusable knowledge.

| Round | Subject | External verdict | The defect that failed it | How it closed |
|---|---|---|---|---|
| R1 | `0ddf00be` / `7c0fa362` | FAIL | branch policy self-authored as `codex/*`; custom evidence schema; stale receipt subject | moved to `repair/*`; adopted `SWOF-EVIDENCE-RETURN-PACK/1` |
| R2 | `be036588` / `0c627817` | FAIL | (a) consumption receipt internally bound to the rejected SHA; (b) canonical source dispositions collapsed into execution labels; (c) PD04 packet said `PLANNED_NOT_DISPATCHED` despite real mutation; (d) test bytes not bound to HEAD | two-axis source/execution disposition split; real spine lifecycle; HEAD-stamped logs |
| R3 | `ed28b784` / `6b0e11e` | FAIL | (a) no real ExecutionBinding — only a convention string; (b) ordering oracle wall-clock-only and self-contradictory; (c) raw evidence set incomplete; (d) pre-mutation receipt falsely claimed direct final-subject linkage | see R4 |
| **R4** | **`7e1f912d` / `206ab073e`** | **local PASS (3 independent lanes)** | the four R3 blockers | authoritative binding + monotonic ordering + full raw evidence + transitive linkage |

### The four R3 blockers and their R4 closures

1. **`W1-R3-EXT-001` — ExecutionBinding never materialized.**
   *Closed by:* finding the **authoritative HGK contract**, which already existed —
   schema `RP002-EXECUTION-BINDING/2`, example at
   `Fabric/stage/RP002-STAGE-HGK/B1/B1_EXECUTION_BINDING.json`, materialization path
   `HG-KSEOS/var/rp002-stage1/b1_pipeline.py`, referenced from `HG-KSEOS/AGENTS.md` §9.
   The R4 run materialized `BIND-SWOF-W1-R4-001` with all eight sections
   (`normative/routing/delegation/lease/budget/idempotency/runtime/terminal`) plus
   `PROFILE_EFFECTIVE_READBACK` proving `ROLE ≠ PROFILE ≠ WORKER`, and the lease
   **read back** from the spine `leases` table.
   > **Lesson:** the authoritative object usually already exists. Search HGK source before
   > inventing a local convention.

2. **`W1-R3-EXT-002` — ordering oracle wall-clock-only AND self-contradictory.**
   *Closed by:* switching the oracle to `project_transitions.rowid` written by
   `hg_kseos.lifecycle.ProjectLifecycleController` — a **DB-generated, append-only,
   contiguous** key the writer cannot choose, and demoting wall-clock to supporting
   metadata. The real lifecycle edge `WORKORDERS_ADMITTED → EXECUTING` *is* "admission
   closed → mutation permitted".
   Proven ordering: `binding_seq 8 < permit_seq 9 < first_write_seq 10`.
   > **Lesson:** never write `wall_clock_only: false` while your own verdict file admits
   > the oracle is host-clock-only. The reviewer will diff the two documents.

3. **`W1-R3-EG-001` — raw evidence set incomplete.**
   *Closed by:* shipping **raw artifacts, not booleans** — the five compiler subcommand
   receipts, `PD04_PACKET`, `TASKSPEC_RAW`, `WORKORDER_RAW`, `ECP_RAW`,
   `EXECUTION_BINDING_RAW`, `PROFILE_EFFECTIVE_READBACK`, `MUTATION_PERMIT_RECEIPT`,
   `ORDERED_LIFECYCLE_EVENT_SLICE`, `BOUNDED_DIFF_WRITESET_RECEIPT`, and six
   `SWOF-GATE-CALIBRATION/1` rows.
   > **Lesson:** `compiler_lint_activation_acceptance_compile_pass = true` is a claim,
   > not proof. The reviewer explicitly refused it.

4. **`W1-R3-EXT-003` — pre-mutation receipt falsely claimed direct final-subject linkage.**
   *Closed by:* `subject_type: PRE_MUTATION_BASELINE_WORKORDER`,
   `direct_final_subject_match: false`, no final SHA present, and a
   `TRANSITIVE_MUTATION_LINEAGE` edge in `FIRST_MUTATION_ORDERING_RECEIPT.json`.

## 1.4 Defect classes to watch for (learned the hard way)

These are the recurring failure modes across R1–R4. Each is now guarded mechanically.

1. **Receipt asserts something untrue.** "FIXED" claimed before the edit landed; ordering
   receipt claiming `wall_clock_only:false` while the verdicts file said otherwise.
   → *Guard:* write-then-read-back assertions; never claim before verifying.
2. **Local-file hashes vs committed blob hashes.** Python wrote CRLF; git normalizes blobs
   to LF; the manifest hashed local bytes and disagreed with the remote.
   → *Guard:* hash **committed blob bytes** (`git cat-file blob`), and include a
   `manifest_hash_source: COMMITTED_GIT_BLOB_BYTES` field.
3. **Vacuous or mis-parsed test counts.** A harness reported `ran: 0` for every root while
   claiming all-green, because `unittest` writes to **stderr** and only stdout was parsed.
   Same class: a checker's scratch script reported `TOTAL: 106` because it used a different
   discovery top-level dir than the logged commands.
   → *Guard:* parse stdout+stderr; reproduce the exact logged invocation; verify
   `defined == collected`.
4. **Evidence carrying the wrong subject.** A regenerated receipt silently kept the
   *rejected* SHA; superseded-subject artifacts remained inside the new pack; a pre-mutation
   artifact was marked as directly bound to a future SHA.
   → *Guard:* per-item `linkage_mode` (`DIRECT_FINAL_SUBJECT` /
   `TRANSITIVE_PRE_MUTATION_LINEAGE` / `WORKORDER_CHECKPOINT` / `COMPILER_CONTRACT_BOUND`)
   and an internal-subject check per mode. Hash match alone is **insufficient**.
5. **Artifacts created at the wrong time.** A binding/RepoContext that must exist *before*
   mutation was generated after it. Fixing such an artifact in place is **retroactive
   fabrication**.
   → *Guard:* pre-mutation objects carry `captured_before_mutation: true`; the evidence
   step refuses to overwrite them. Corrections require a **full replay from the baseline**,
   never an in-place edit.
6. **Overwriting a frozen subject.** Re-running the chain silently moves the candidate's
   verification base.
   → *Guard:* verify the checker's PASS before freezing; do not re-run for cosmetic fixes.

## 1.5 Architecture / protected invariants (do NOT reopen without a new defect)

```text
source disposition and execution disposition are ORTHOGONAL axes
  - an execution label (DEFERRED/CONSUMED_ACTIVE/...) can NEVER be written as a source_disposition
  - canonical tokens are preserved verbatim: SELECTED_FOR_PREDEV, ADOPT_WITH_ADAPTER,
    ADOPT_WITH_ADAPTER_CONDITIONAL_ON_DOC09, REJECTED_FOR_PRIMARY_POLICY_SLOT, REUSE_AS_REFERENCE
  - unknown source tokens fail closed (TEMP_CLOSED_REGISTRY_ROW); vocabulary is never invented
branch policy: candidate branches must match wo/* or repair/*
five-file capability repair surface is authoritative; the five files are byte-identical
  to the reviewed R2 subject 8689e583
six-root test topology (tests, src/fabric/tests, src/knowledge/tests,
  src/admission/tests, src/profile/tests, src/capability/tests) = 113 tests
test-hygiene guard: no test may be defined after an `if __name__ == "__main__"` guard
maker/checker separation; the checker never repairs the candidate
providers OPA / OpenLineage / OpenFGA / Cedar remain DEFERRED / unbound — no activation
```

## 1.6 Verification — how to reproduce the exact-HEAD qualification

`src/` is not an importable package root, so each subsystem test root is discovered
separately. **Use these exact commands** — the `-t` top-level differs per root, and using
the wrong one silently under-reports the count:

```bash
python -m unittest discover -s tests -t .                                  # 16 tests
python -m unittest discover -s src/fabric/tests -t src/fabric/tests        # 21 tests
python -m unittest discover -s src/knowledge/tests -t src/knowledge/tests  # 25 tests
python -m unittest discover -s src/admission/tests -t src/admission/tests  # 17 tests
python -m unittest discover -s src/profile/tests -t src/profile/tests      # 12 tests
python -m unittest discover -s src/capability/tests -t src/capability/tests # 22 tests
```

Aggregate: **113 tests**, 0 failures, 0 errors, 0 skipped.

> `unittest` prints its summary to **stderr** — capture both streams or you will read 0.

## 1.7 Open residuals (disclosed, not hidden)

1. **Append-only ordering is by convention, not cryptographically enforced.** SQLite permits
   an explicit `rowid` on INSERT, so "the writer cannot choose the key" rests on using the
   `ProjectLifecycleController` API. There is no DB trigger or hash-chain.
2. **No dedicated `execution_bindings` table in the HGK spine.** The binding is a
   materialized `RP002-EXECUTION-BINDING/2` artifact attached to the `WORKORDERS_ADMITTED`
   spine row via `evidence_refs_json`.
3. **No remote CI runs** for the source SHA (remote CI is conditional on portable checks).
4. **No provider-off runtime drill** — no provider is activated or bound.

## 1.8 Next steps — how to start W2

1. **Do not modify `repair/w1-r4-binding-order-proof`.** It is the frozen R4 subject under
   external read. Adding commits moves `7e1f912d` and invalidates the published readset.
2. Wait for the R4 external challenge verdict on `7e1f912d` + `206ab073e`.
3. On PASS, W2 may be dispatched **from a fresh branch off the accepted W1 subject**, under a
   new WorkOrder, following the same spine:
   `fresh RepoContext → PD04 packet → Requirement/TaskSpec/WorkOrder → ExecutionBinding → mutation permit → (monotonic seq) → mutation → exact-HEAD tests → fresh checker → evidence pack → readset`.
4. Carry forward: the pre-mutation objects must be captured **before** mutation; the raw
   evidence set must be complete; linkage modes must be honest.
5. Not authorized without a new order: merge, Release, Production, world effect, W2–W5 dispatch.

---

# 2. 相關記憶索引 (Memory Index)

## 2.1 Governance / control plane

| Ref | Path |
|---|---|
| HGK root (sole normative control plane) | `C:\Projects\Agent_Workspace\HG-KSEOS` |
| HGK operating rules | `HG-KSEOS\AGENTS.md` |
| Fabric contract surface (READ-ONLY) | `C:\Projects\Agent_Workspace\Fabric` |
| Source corpus (READ-ONLY) | `知識庫\實作相關DOC\Fabric vNext\Semantic World OS Fabric\SWOF-F_SWOF-GENIE_All-IW_Pre-Dev_Multi-Packages` |
| Project runbook | `…\Multi-Packages\SWOF_HGK_ACA_RBWI\SWOF_HGK_ACA_RBWI.md` |
| Prompt compiler bundle | `知識庫\實作相關DOC\HG-KSEOS\construction-acceptance-prompt-compiler\construction-acceptance-prompt-compiler` |

## 2.2 Authoritative HGK objects discovered during R4 (reuse these, don't reinvent)

| Concept | Authoritative locator |
|---|---|
| **ExecutionBinding schema** | `RP002-EXECUTION-BINDING/2` — example `Fabric\stage\RP002-STAGE-HGK\B1\B1_EXECUTION_BINDING.json`; materializer `HG-KSEOS\var\rp002-stage1\b1_pipeline.py`; referenced from `HG-KSEOS\AGENTS.md` §9 |
| **Normal lifecycle** | `HG-KSEOS\src\hg_kseos\lifecycle.py` — `ProjectLifecycleController`, states `PROJECT_CREATED → … → WORKORDERS_ADMITTED → EXECUTING → VERIFYING → …` |
| **Monotonic ordering key** | `project_transitions.rowid` and `canonical_events.rowid` (append-only, DB-generated) |
| **Typed spine API** | `HG-KSEOS\src\hg_kseos\spine.py` — `SharedSpine` (`register_requirement`, `transition_requirement`, `create_taskspec`, `create_workorder`, `record_workorder_result`, `register_evidence`, checkpoints) |
| **Spine schema** | `HG-KSEOS\src\hg_kseos\schema.sql` |
| **Profiles** | `hgk-orchestrator`, `hgk-coding-factory`, `hgk-engineering-reviewer`, `hgk-qa`, `hgk-security`; `ROLE ≠ PROFILE ≠ WORKER` |
| **Canonical source dispositions** | `PI-PKG/SWOF-F_SWOF-GENIE_All-IW_PI-PKG-05_2026-09-14_r2_FULL_REPAIR.md#sha256=a9d733c7… §19.1 L3595–L3605` and `L10618` |

## 2.3 Evidence and run artefacts (HG-KSEOS side)

| Round | Evidence dir | Key files |
|---|---|---|
| Pre-construction | `HG-KSEOS\evidence\swof-precon-001\` | dossier, accepted ZIP, PD04 graph |
| Construction | `HG-KSEOS\evidence\swof-construction-002\` | closure, source_drift, github readset |
| W1 R2 | `…\w1_narrow_repair\` | R2 pack (superseded) |
| W1 R3 | `…\w1_r3_admission_order\` | R3 pack (superseded) |
| **W1 R4 (current)** | `…\w1_r4_binding_order\` | `PRE_MUTATION_ADMISSION_RECEIPT.json`, `EXECUTION_BINDING_RAW.json`, `MUTATION_PERMIT_RECEIPT.json`, `FIRST_MUTATION_ORDERING_RECEIPT.json`, `EXACT_HEAD_QUALIFICATION.json`, `GATE_CALIBRATION_ROWS.json`, `SWOF_EVIDENCE_RETURN_PACK.json`, `SWOF_EXTERNAL_ACCEPTANCE_READSET.json`, `compiler_raw/` |
| R4 governed spine | `HG-KSEOS\var\swof-construction-002-r4\hgk_spine.sqlite3` |

## 2.4 Reproducer scripts (HG-KSEOS side, `var\swof-construction-002\`)

```text
r17_r4_compiler.py    build the R4 C0-C9 contract + run the canonical compiler, persist RAW receipts
r18_bind_admit.py     STEP 1 (no source mutation): lifecycle drive, requirement/taskspec/workorder,
                      authoritative RP002-EXECUTION-BINDING/2, profile readback, mutation permit,
                      pre-mutation receipts, pre-mutation RepoContext, pre-mutation PD04 chain
r19_apply.py          STEP 2 (the ONLY step that may mutate source): asserts the permit first
r20_r4_evidence.py    exact-HEAD qualification + complete raw evidence set + gate calibration
r22_pack_r4.py        LocalClosure/IndependentReceipt, RETURN-PACK with linkage modes,
                      5 zero-count validation, publication + new/reused PR
r7_receipt.py         named-capability consumption receipt generator (canonical locators + digest)
```

## 2.5 Reporting / claim discipline (user-facing rules)

```text
always separate:  已實作  |  本地+獨立複驗 PASS  |  外部驗收 PASS
never promote a local PASS to external acceptance
state the "尚未完成" list explicitly
verification before freeze: do not re-run a chain once a checker has passed it
corrections to pre-mutation artefacts require a full replay, never an in-place edit
```

---

# 3. Layout

```text
AGENTS.md              operative agent constitution
docs/constitution/     authority / non-goals
schemas/authority/     machine-checkable authority guards (W0)
schemas/pd04/          construction-packet route guards (W0-003)
schemas/fabric/        narrow-waist + CapabilityContract guards (W1-001)
schemas/knowledge/     source-trust orthogonality + retrieval lifecycle (W1-002)
schemas/admission/     admission-ladder guards (W1-003)
schemas/capability/    named-consumption schema + conformance sample (W1 repair)
tools/pd04/            PD04 construction-packet factory (W0-003)
src/fabric/            provider-neutral narrow waist + binder (W1-001)
src/knowledge/         Data Brain: trust facets, retrieval, source-as-DATA (W1-002)
src/admission/         Search-Before-Build admission ladder (W1-003)
src/profile/           PD05 execution-context seam (W1 repair)
src/capability/        named-capability consumption ledger (W1 repair)
tests/, src/*/tests/   test suites (each subsystem root is discovered separately)
config/                workspace + runtime configuration
```

`src/<subsystem>/` is granted to W1+ by the admitted write-sets; W0 itself introduces no
semantic implementation. Each subsystem owns its own test root under `src/<subsystem>/tests/`.

A structural hygiene guard (`tests/test_test_hygiene.py`) fails the suite if any test is
defined after an `if __name__ == "__main__"` guard, since such tests are silently never
collected.

# 4. Authority

HG-KSEOS is the sole governance/normative control plane. This repository is a *product*
root: it holds implementation and never semantic authority.

# 5. Non-claims

Not externally accepted, not released, not production; no runtime or world-effect claim.
W2–W5 are `PLANNED_NOT_DISPATCHED`. `NO_REMOTE_MERGE`, `NO_RELEASE`, `NO_PRODUCTION`,
`NO_WORLD_EFFECT_ACCEPTANCE`.
