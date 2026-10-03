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
repository, which is unreviewed W0-W2 work.

## Status

**W0, W1 and W2 complete locally.** W3-W5 are `PLANNED_NOT_DISPATCHED`.

| Wave | Scope | State |
|---|---|---|
| W0 | constitution, repo foundation, PD04 packet factory | IMPLEMENTED + INDEPENDENTLY VERIFIED |
| W1 | `src/fabric`, `src/knowledge`, `src/admission`, `src/profile`, `src/capability` | IMPLEMENTED + INDEPENDENTLY VERIFIED |
| W2 | `src/security`, `src/effect`, `src/assurance`, `src/observability` | IMPLEMENTED (LOCAL) / PENDING INDEPENDENT CHECK |
| W3-W5 | product surfaces, ops/research, migration/handoff | PLANNED_NOT_DISPATCHED |

**This is a W2-stage snapshot with a REDUCED claim.** It is NOT externally accepted,
NOT released, NOT production. External acceptance of W0-W5 as a whole has not been
performed and must not be inferred from any verdict on this snapshot.

## Layout

```text
AGENTS.md              operative agent constitution
docs/constitution/     authority / non-goals
schemas/authority/     machine-checkable authority guards (W0)
schemas/pd04/          construction-packet route guards (W0-003)
schemas/fabric/        narrow-waist + CapabilityContract guards (W1-001)
schemas/knowledge/     source-trust orthogonality + retrieval lifecycle (W1-002)
schemas/admission/     admission-ladder guards (W1-003)
schemas/security/      permission-envelope + security-veto guards (W2-001)
schemas/effect/        effect-record guards (W2-002)
schemas/assurance/     acceptance-predicate + evidence-plan guards (W2-003)
schemas/observability/ shape projections of the witness layer (W2-004)
tools/pd04/            PD04 construction-packet factory (W0-003)
src/fabric/            provider-neutral narrow waist + binder (W1-001)
src/knowledge/         Data Brain: trust facets, retrieval, source-as-DATA (W1-002)
src/admission/         Search-Before-Build admission ladder (W1-003)
src/profile/           PD05 execution-context seam (W1 repair)
src/capability/        named-capability consumption ledger (W1 repair)
src/security/          least privilege, source-as-DATA, injection quarantine,
                       secret/PII redaction, rights/HumanGate, supply-chain
                       identity, security veto (W2-001)
src/effect/            intent/attempt/observation/readback/reconciliation,
                       UNKNOWN_EFFECT (W2-002)
src/assurance/         predicate, deterministic oracle, evidence plan, SoD,
                       read-only journal-integrity envelope (W2-003)
src/observability/     correlation, redaction, hooks, recovery (W2-004)
tests/, src/*/tests/   test suites (each subsystem root is discovered separately)
config/                workspace + runtime configuration
```

`src/<subsystem>/` is granted to W1+ by the admitted write-sets; W0 itself introduces no
semantic implementation. Each subsystem owns its own test root under `src/<subsystem>/tests/`.

## Verification

`src/` is not an importable package root, so each subsystem test root must be
run separately. All ten roots are green:

```bash
python -m unittest discover -s tests -t .                                  # 16 tests
python -m unittest discover -s src/fabric/tests -t src/fabric/tests        # 21 tests
python -m unittest discover -s src/knowledge/tests -t src/knowledge/tests  # 25 tests
python -m unittest discover -s src/admission/tests -t src/admission/tests  # 17 tests
python -m unittest discover -s src/profile/tests -t src/profile/tests      # 12 tests
python -m unittest discover -s src/capability/tests -t src/capability/tests # 22 tests
python -m unittest discover -s src/security/tests -t src/security/tests    # 159 tests
python -m unittest discover -s src/effect/tests -t src/effect/tests        # 91 tests
python -m unittest discover -s src/assurance/tests -t src/assurance/tests  # 95 tests
python -m unittest discover -s src/observability/tests -t src/observability/tests # 97 tests
```

Aggregate: **555 tests**, 0 failures, 0 errors, 0 skipped.

A structural hygiene guard (`tests/test_test_hygiene.py`) fails the suite if any test is defined after an `if __name__ == "__main__"` guard, since such tests are silently never collected.

## Authority

HG-KSEOS is the sole governance/normative control plane. This repository is a *product*
root: it holds implementation and never semantic authority.

## Non-claims

Not externally accepted, not released, not production; no runtime or
world-effect claim.

- W2 is NOT externally accepted: the W2 suites are green locally only, and W2 is
  `PENDING INDEPENDENT CHECK`. Local green is not acceptance.
- The W2 journal-integrity envelope is DETECTION-ONLY over an EXPORTED event stream. It makes
  no DB-level claim and no signature claim: there is no key management, so it cannot prove
  authorship or make the source database tamper-proof.
- W2 performs no live effect: its fixtures are local/simulated only. Naming a provider does not
  activate it.