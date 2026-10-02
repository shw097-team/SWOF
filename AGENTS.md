# AGENTS.md — SWOF construction agent contract

Authority: compiled from `PI-PKG-00` §2.1–§2.5 and `SWOF_HGK_ACA_RBWI.md` §10.
This file is the operative constitution for any agent mutating this repository.

## 1. Authority stack (PI-PKG-00 §2.1 — order is normative, do not renumber)

```text
P0  Current user task / this production instruction
 ↓
P1  All-IW process / integration SSOT
 ↓
P2  Original SWOF-F / SWOF GENIE design intent
 ↓
P3  Current SWOF-F / SWOF GENIE owner architecture / upgrade design
 ↓
P4  Accepted derived blueprints / package blueprints / DOC blueprints / substantive DOCs
 ↓
P5  Donor corpora
 ↓
CONTROL  PORTABLE_MOUNT_PROFILE + owning GRP surfaces
 ↓
SUPPORT  2026 official web / GitHub / arXiv / Hugging Face / engineering community
```

`CONTROL` owns mount/router/security/evidence surfaces only where the profile says so. It does
**not** acquire Product Truth or Semantic Truth. `SUPPORT` content is never authority.

## 2. Exactly one Canonical Plan IR (PI-PKG-00 §2.3)

`canonical_plan_ir_count = 1`.

Product IR, Stack IR, SQS IR, package views, provider profiles, OpenSpec artifacts, Spec Kit
artifacts, GSD files and vendor schemas may exist **only** as projections or adapters. Promoting
any of them to a second parent semantic root is a defect (`docs/constitution/authority.md` §5).

## 3. Truth separation (PI-PKG-00 §2.4)

| Truth class | Owner |
|---|---|
| System / Semantic Truth | canonical semantic owners only |
| Product Truth | Human / Product owners only |
| External Formal Truth | remains external |
| Execution Truth | provider/tool runtime state — replaceable, never semantic authority |
| Evidence Truth | subject/version/environment/oracle/checker-bound; green execution does not inherit acceptance |
| Claim Truth | may be lowered automatically by stale evidence; raising it needs proper authority + evidence |

## 4. Equal-rank conflict (PI-PKG-00 §2.5)

```text
DETECT → SOURCE-ID CHECK → SUPERSESSION CHECK → OWNER CHECK →
ORIGINAL-INTENT CHECK → CONFLICT RECORD → ADJUDICATE or TEMP_CLOSED → AFFECTED INVALIDATION
```

Model convenience, recency alone, popularity and web ranking are **not** tie-breakers.
A true equal-rank constitutional conflict is a Human authority edge: stop the affected branch.

## 5. Mutation law (RBWI §10.2 / §10.4)

Every repo-mutating WorkOrder must carry `fresh_repocontext_ref`, `pd04_packet_ref`,
`taskspec_ref`, `ecp_ref` and exact requirement/acceptance/evidence edges. Missing any one
⇒ `FAIL_PD04_ROUTE`. Package number is not coding order; the WorkOrder is the mutation unit.

## 6. Supersession lock (PI-PKG-00 §2.2)

A source surfaced only as older-revision provenance (`r2`/`r3` of a subject whose current
revision is `r4`) is **provenance-only** and cannot be used to build current requirements.

## Non-claims

This repository is a product root under HG-KSEOS governance. It does not own semantic authority,
does not constitute external acceptance, and is not released or production.
