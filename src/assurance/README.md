# Assurance / evidence / SoD substrate (W2, WO-SWOF-W2-003)

The substrate that **decides PASS/FAIL**. Its central law is the reason it exists:

```text
a checker or oracle that CANNOT fail is the defect.
```

So every rejection class below is a typed error with its own `reason_code`, every one is
injected by an adversarial test, and no assertion is initialised and left unreachable.

## Truth separation (do not blur these)

```text
green execution   != acceptance
observed          != verified
digest match      != meaning        (hash integrity proves transport, not subject)
summary boolean   != evidence
independent run   != independent checker
manifest intact   != DB tamper-proof
```

## Modules and the failure mode each one prevents

- `predicate.py` - the falsifiable unit of assurance. An empty oracle, an empty evidence
  requirement, an empty negative-fixture set, an unknown subject type, or a terminal-state set
  with fewer than two members is refused with `PredicateInvalid` and a specific `reason_code`.
  The RAW mapping is validated before construction, so malformed input never leaks a generic
  `TypeError`. `digest` covers immutable semantic content only (runtime binding state is
  excluded), so a predicate that differs only in a runtime field cannot collide.
- `oracle.py` - turns (predicate, items) into an `OracleVerdict`. FIRST-FAILURE: a documented,
  stable condition ladder that stops at the first failure. An `oracle_id` with no defined rules
  raises `OracleAmbiguous`. Missing kind, duplicate kind, wrong subject and non-deterministic
  ordering each return a distinct `reason_code`. `decide` never returns passed=True while any
  declared negative fixture is unrepresented in the checked set.
- `evidence.py` - raw-proof, subject, environment and linkage binding. A summary boolean with no
  raw artifact is `FORGED_SUMMARY`; a plausible artifact with the wrong hash is `HASH_MISMATCH`;
  a pre-mutation object sold as direct-final is `DIRECT_FINAL_CLAIM_ON_PRE_MUTATION`; a moving
  branch tip sold as an immutable SHA is `BRANCH_TIP_SUBSTITUTION`; stale, foreign,
  self-referential and maker-as-checker items each have their own reason. `validate_plan` keeps
  the per-linkage-mode counters **separate** (one mixed counter both over- and under-reports)
  and never passes on an empty item list. `invalidate` returns the invalidation cone for a
  changed identity (subject SHA, oracle id, environment, security config).
- `sod.py` - `assert_separated` returns a SoD receipt or raises `SoDViolation` when the producer
  and checker are the same or empty identity. `ReadOnlyChecker.write_product` **always** raises
  `CheckerWriteRefused`; a checker may not repair the candidate, its evaluator logic, the
  WorkOrder or the evidence contract. `write_evidence` is allowed only inside the declared
  evidence root. Every read and every refused write is recorded in the receipt, so the
  enforcement is demonstrable rather than asserted.
- `journal.py` - W2-JOURNAL-INTEGRITY-ASSESSMENT: a digest chain over an **EXPORTED** lifecycle
  stream. `entry_digest = sha256(chain_id | seq | event_id | prev_digest | canonical_json(payload))`
  and the genesis is chain-bound, so a foreign chain cannot be spliced in. `verify` distinguishes
  payload mutation (`ENTRY_DIGEST_MISMATCH`), removal/truncation (`SEQ_GAP`), reordering
  (`PREV_DIGEST_MISMATCH`), foreign chain (`CHAIN_ID_MISMATCH`) and header tampering
  (`HEADER_MISMATCH`). It never writes to HGK.

## The journal envelope is DETECTION-ONLY (non-claims)

- It gives DETECTION of post-export modification of the exported event stream.
- It does **NOT** make the HGK database tamper-proof.
- It is **NOT** a cryptographic signature (there is no key management).
- It is read-only with respect to HG-KSEOS (it never writes to HGK).
- It should **NOT** be backported into the accepted W1 subject for evidence aesthetics.

## Running the tests

```text
python -m unittest discover -s src/assurance/tests -t src/assurance/tests
```

Python 3.11+, standard library only. Deterministic: no wall-clock in a decision, no randomness,
stable ordering everywhere.