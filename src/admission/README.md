# Admission / Search-Before-Build seam (W1-003)

Source basis: `PI-PKG-05` H1-05 / §19 (Search-Before-Build, Technology Admission, External
Capability Reuse) and the `D02-TECH-ADOPTION-LEDGER`.

## Admission ladder (strength order is normative)

```text
REUSE > WRAP > TRANSLATE > ADAPT > COMPOSE > BUILD_MINIMUM > BUILD_NEW_EXCEPTION
```

- **Popularity is not qualification.**
- `BUILD_MINIMUM` requires a documented material gap.
- `BUILD_NEW_EXCEPTION` requires evidence that *all* earlier dispositions fail materially.
- **`selected != installed != qualified != active`** — each is a separate gate.
- A fixed selection must not be silently downgraded (anti-downgrade).
- A `REJECTED_FOR_PRIMARY_POLICY_SLOT` technology (e.g. Cedar) cannot be activated.
- Activation requires provider-off / uninstall-exit / rollback / drift-trigger to be present.
