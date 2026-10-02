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
repository, which is unreviewed W0 work.

## Status

**W0 only** - constitution and repository foundation. W1-W5 are `PLANNED_NOT_DISPATCHED`.

## Layout (W0)

```text
AGENTS.md              operative agent constitution
docs/constitution/     authority / non-goals
schemas/authority/     machine-checkable authority guards
tests/                 W0 bootstrap tests
config/                workspace + runtime configuration
```

`src/` is deliberately **absent**: the admitted write-sets grant `src/<subsystem>/` to
W1+ only (W1-001 `src/fabric`, W1-002 `src/knowledge`, ...). No semantic implementation
may land in W0.

## Verification

```bash
python -m unittest discover -s tests -t .
```

## Authority

HG-KSEOS is the sole governance/normative control plane. This repository is a *product*
root: it holds implementation and never semantic authority.

## Non-claims

Not externally accepted, not released, not production; no runtime or
world-effect claim.
