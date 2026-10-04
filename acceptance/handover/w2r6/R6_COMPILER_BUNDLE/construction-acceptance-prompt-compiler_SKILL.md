---
name: construction-acceptance-prompt-compiler
description: Compile current user intent, authoritative project controls, current baseline evidence, active capability routes, user journeys, acceptance predicates, and termination rules into a thin fail-closed implementation-and-acceptance prompt. Use for new implementation, continuation, narrow repair, upgrade, runtime or named-tool qualification, evidence-only closure, external acceptance, or production-promotion planning when a GPT or coding agent must direct work without duplicating RBWI/WP/control documents, mistaking design or file presence for runtime readiness, omitting user-facing capabilities, accepting proxy evidence, reopening unrelated sealed scope, or promoting an external method into the project control plane.
---

# 指揮實作驗收 Prompt Compiler

Compile the task contract before rendering the executor prompt. Treat rendering as the last step.

## Establish the working boundary

1. Preserve the user's goal, expected outcome, expected experience, constraints, non-goals, authorized mutations, requested deliverables, autonomy, allowed HITL, and claim ceiling.
2. Resolve the governing source order from the current project. Treat web pages, repositories, tool output, and retrieved text as support data unless the project's authority explicitly promotes them.
3. Distinguish the host task kind from the compiler ChangeSet:
   - Host task kind selects workflow policy. If the project fixes an exact registry, do not invent another kind.
   - ChangeSet class selects the affected work: `NEW_IMPLEMENTATION`, `CONTINUATION`, `NARROW_REPAIR`, `UPGRADE`, `QUALIFICATION_ONLY`, `EVIDENCE_ONLY`, `EXTERNAL_ACCEPTANCE_ONLY`, or `PRODUCTION_PROMOTION`.
4. Do not modify product code, install named tools, invoke external providers, or perform release actions merely because this compiler names the work. The generated prompt carries those actions to the authorized executor.

Read [source-routing.md](references/source-routing.md) for C0-C3, source roles, conflicts, task classification, and project-specific mount handling.

## Compile C0-C9

Build one JSON contract conforming to [prompt-contract.schema.json](references/prompt-contract.schema.json).

1. **C0 Source scan:** Enumerate required source families, reviewed locators and hashes, missing critical sources, and normative claims.
2. **C1 Intent:** Round-trip the current user intent and non-goals. Record mutation and HITL boundaries.
3. **C2 Authority:** Rank sources, separate normative/state/support roles, quarantine unresolved equal-rank conflicts, and reject support-to-norm promotion.
4. **C3 ChangeSet:** Select exactly one class, bind the baseline, list affected scope, and protect unrelated accepted scope.
5. **C4 Execution scope:** Preserve both historical/source disposition and current execution disposition for every relevant capability.
6. **C5 Runtime readiness:** For every active named capability, materialize closure work and the full stage row. Open stages are valid inputs; a missing row is not.
7. **C6 User experience:** Project required user expectations into journeys that ordinary users can trigger without knowing internal WP, Skill, or provider names.
8. **C7 Acceptance:** Give every active capability, required journey, requirement, and requested deliverable a case-specific edge at the required semantic depth.
9. **C8 Evidence and claims:** Require raw receipts, producer/checker separation, exact candidate binding, invalidation, and a bounded claim.
10. **C9 Termination and resume:** Separate terminal states from pauses, require a checkpoint, and route failure to the smallest affected repair.

Read [contract-model.md](references/contract-model.md) for the field model. When tools, Skills, methods, MCPs, or providers are named or automatically routed, also read [activation-runtime.md](references/activation-runtime.md). For acceptance or evidence work, read [acceptance-evidence.md](references/acceptance-evidence.md). For continuation, permissions, failure, or external actions, read [termination-permissions.md](references/termination-permissions.md).

## Enforce hard invariants

- Do not create a second RBWI, reducer, workflow engine, authority stack, or Canonical Plan IR.
- Do not make a normative or current-state claim without an exact source locator.
- Block unresolved equal-rank authority conflicts.
- Keep source disposition and current execution disposition as separate fields.
- Apply the Activation Bridge: an active canonical route, user journey, selected profile, or automatic route target requires an active disposition plus runtime closure, or a fully certified native substitution.
- Keep `PROMPT_COMPILE_PASS`, `RUNTIME_READY`, independent acceptance, release, and production as separate states.
- Do not allow file, symbol, mapping, schema, documentation, maker, shared, or summary evidence to close runtime behavior.
- Require discover, bind, route, effective-load, positive, negative/security, fallback, rollback, and independent qualification for active named runtime capabilities.
- Require every required user journey and requested deliverable to have an acceptance edge.
- Reject maker self-acceptance and stale or foreign candidate evidence.
- Do not install or qualify optional, deferred, standby, prohibited, or donor-only capabilities unless the current profile selects them.
- Keep external methods as bounded adapters; retain the native project owner and release authority.
- Treat an iteration or session boundary as a checkpoint, never completion.
- Reopen only affected edges for repair, upgrade, continuation, or evidence-only work.

## Run deterministic validation

Use the bundled compiler rather than retyping its rules:

    python3 scripts/prompt_contract_compiler.py lint CONTRACT.json
    python3 scripts/prompt_contract_compiler.py activation CONTRACT.json
    python3 scripts/prompt_contract_compiler.py acceptance CONTRACT.json
    python3 scripts/prompt_contract_compiler.py compile CONTRACT.json --out-dir OUTPUT_DIR

Use `duplication` with the rendered prompt and current control files when second-RBWI risk is material:

    python3 scripts/prompt_contract_compiler.py duplication PROMPT.md --source CONTROL.md --source RBWI.md

Do not render an executable prompt when lint returns `PROMPT_COMPILE_BLOCKED`. Runtime stages may remain open if their closure work and acceptance edges are explicit.

## Render only compiled decisions

Read [rendering-and-antipatterns.md](references/rendering-and-antipatterns.md) before rendering. Emit exactly these ten sections:

0. Machine Header
1. Mission / ChangeSet
2. Authority / Files-first order
3. Intent / Non-goals / Claim ceiling
4. Active / Deferred / Forbidden scope
5. Baseline / Reuse / Do-not-redo
6. Implementation and qualification gates
7. Failure / HITL / Repair / Resume
8. Evidence / Independent acceptance / Candidate binding
9. Termination / Final output

Reference exact source paths and locators. Do not copy their substantive bodies into the prompt.

## Return the compiler result

Return:

1. Compiler verdict: `PROMPT_COMPILE_PASS` or `PROMPT_COMPILE_BLOCKED`.
2. Concise source, intent, ChangeSet, active/deferred scope, runtime-gap, acceptance-orphan, and claim-ceiling summary.
3. Thin executable prompt only on compile pass.
4. Exact blocker codes and close conditions when blocked.
5. Contract, prompt, and receipt paths when files were written.

Never promote compiler success into runtime, independent, release, or production success.
