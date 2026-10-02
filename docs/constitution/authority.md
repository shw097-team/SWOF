# Authority constitution

Compiled from `PI-PKG-00` §2.1–§2.5 (H1-01, Package-00 primary non-degradable chapter) and
`SWOF_HGK_ACA_RBWI.md` §10.2.

## 1. Stack order

The eight-level order in `AGENTS.md` §1 is normative and preserves the user's explicit ordering.
No agent may renumber, re-rank or collapse levels.

## 2. Supersession

A subject's current revision is ACTIVE_NORMATIVE. Older revisions are
ARCHIVED_SUPERSEDED_DISABLED and are provenance-only. Searching must never silently resurrect
an older revision into a requirement.

## 3. Single parent semantic root

`canonical_plan_ir_count = 1`. A destructive test must fail if any projection is promoted to a
second parent semantic root (see `schemas/authority/canonical_plan_ir.schema.json`).

## 4. Truth classes

Six classes (`AGENTS.md` §3). Execution Truth is replaceable and never becomes semantic
authority. Evidence Truth is bound to subject/version/environment/oracle/checker; a green run
does not inherit acceptance.

## 5. Projections and adapters

Permitted **only** as projection/adapter: Product IR, Stack IR, SQS IR, package views, provider
profiles, OpenSpec artifacts, Spec Kit artifacts, GSD files, vendor schemas.

## 6. Equal-rank conflict resolution

The eight-step algorithm (`AGENTS.md` §4). Adjudication of a true equal-rank constitutional
conflict belongs to Human authority; the executor records CONFLICT RECORD and stops the
affected cone with `TEMP_CLOSED`.
