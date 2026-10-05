# Assurance schemas (W2, WO-SWOF-W2-003)

Machine-checkable projections of the assurance substrate in `src/assurance/`. A schema is a
SHAPE check only. Passing a schema is not an acceptance, and a schema never acquires Product or
Semantic truth. The decision laws are enforced in Python, because they are laws, not shapes.

## The contract

```text
acceptance predicate  - the falsifiable unit: a predicate that cannot fail is not a predicate
    required_evidence_kinds non-empty, negative_fixtures non-empty, >= 2 terminal_states
    subject_type in {DELIVERABLE, CAPABILITY, JOURNEY, REQUIREMENT}
oracle                - (predicate, items) -> first-failure verdict; an undefined oracle is
    ambiguous; an unrepresented negative fixture never passes
evidence plan         - raw-proof / subject / environment / linkage binding per required kind
    required entries are [kind, linkage_mode, environment]
segregation of duties - maker != checker; the checker may read the candidate and may write only
    inside the evidence root; it may NEVER write the product
journal envelope      - a DETECTION-ONLY digest chain over an EXPORTED event stream
```

## Files

- `acceptance_predicate.schema.json` - the `AcceptancePredicate` shape. Closed
  (`additionalProperties: false`). `subject_type` is enumerated, `terminal_states` has
  `minItems: 2`, and `required_evidence_kinds` / `negative_fixtures` have `minItems: 1`. The law
  that an empty oracle or an unfalsifiable predicate is `ERR_PREDICATE_INVALID` is enforced in
  `src/assurance/predicate.py`.
- `evidence_plan.schema.json` - the `EvidencePlan` shape. Closed. Each `required` item is a
  3-element array of non-empty strings. The rejection classes (`FORGED_SUMMARY`, `HASH_MISMATCH`,
  `WRONG_SUBJECT`, `DIRECT_FINAL_CLAIM_ON_PRE_MUTATION`, `BRANCH_TIP_SUBSTITUTION`, `STALE`,
  `FOREIGN`, `SELF_REFERENTIAL`, `CHECKER_EQUALS_PRODUCER`, `RAW_PROOF_MISSING`) are enforced in
  `src/assurance/evidence.py`; the per-linkage-mode counters are kept separate so one mixed
  counter cannot both over- and under-report.

## Explicit non-claims

- The journal envelope gives DETECTION of post-export modification only.
- It is NOT a cryptographic signature: there is no key management, so it cannot prove authorship.
- It is NOT DB-level enforcement and does NOT make the HGK database tamper-proof.
- It is read-only with respect to HG-KSEOS: it never writes to HGK.
- A green execution does not inherit acceptance, and a schema pass is not an acceptance.
- It should NOT be backported into the accepted W1 subject for evidence aesthetics.