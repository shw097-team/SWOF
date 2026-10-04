# R6 HGK Normative Closure — Reproducibility

## Machine
- project: HGK-P0-SWOF-W2
- changeset: NARROW_REPAIR Branch A
- final_source_candidate_sha: 94e4c15e1040a159d0eb6ac3ef4089b421e60bf9
- final_checkpoint_id: CK-W2-R6-FINAL
- typed_api_only: true ; no_direct_sql_writes: true

## Storage model (honest)
The W2 normative closure is delivered as an evidence-tree **projection artifact**
(`R6_W2_NORMATIVE_CLOSURE_PROJECTION.json`) bound into the exact evidence commit
`6c58c21eee69391ba146e21e27b6d3b7f8f2211c` — the SAME mode used for R1–R5 (the live shared-spine
database does not carry `HGK-P0-SWOF-W2` rows; those rounds also shipped projection artifacts). This is
the established, reproducible closure representation for SWOF W2.

## Live spine (NOT published — size only)
- db: var/shared-spine/hg-kseos.db (793,894,912 bytes) — withheld from the public mirror by size/no-content-value,
  not by secrecy. It contains no SWOF-W2-specific rows required to reproduce this closure.
- spine tables: acceptances, artifact_contracts, candidates, canonical_events, checkpoints, evidence_refs, evolution_signals, improvement_candidates, kg_assertions, kg_edges, knowledge_docs, knowledge_fts, knowledge_fts_config, knowledge_fts_content, knowledge_fts_data, knowledge_fts_docsize, knowledge_fts_idx, leases, memory_records, project_lifecycles, project_transitions, projects, provider_bindings, release_decisions, requirements, rollback_records, schema_meta, source_units, sources, taskspecs, tt_records, workorders, workspaces
- SharedSpine methods used: register_evidence, resolve_acceptance, record_workorder_result,
  transition_requirement, create_taskspec, create_workorder, acquire_lease/release_lease.
- spine schema fingerprint (sorted table list sha256): b8c2e0ff3fd3f7d3794ec6ce5dce15e1b4f8ac8102b260d54284289c9d02e5d2

## Reproduce
1. Read `R6_W2_NORMATIVE_CLOSURE_PROJECTION.json` (in the evidence subject) — it names the 4 EVD-W2R6-*
   evidence handles with their real sha256, the governed REQ/ACC/WO row, CK-W2-R6OBL-0001 and CK-W2-R6-FINAL.
2. `checkpoints.source_digest` for CK-W2-R6-FINAL resolves to the exact source sha 94e4c15….
3. `project_lifecycle.last_checkpoint_id == CK-W2-R6-FINAL`; denominator non-vacuous (workorders_open=0,
   acceptances_open=0, blocking_open=0).
