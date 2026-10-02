# SWOF / SWOF GENIE

Greenfield construction root for the SWOF / SWOF GENIE system, built under the HG-KSEOS
governance control plane from the frozen pre-construction baseline
(`SWOF-PRECONSTRUCTION-001`, externally accepted).

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
