# Effect schemas (W2, WO-SWOF-W2-002)

Machine-checkable projections of the effect substrate in `src/effect/`. A schema is a shape check
only: passing it is not an acceptance, and it never acquires Product or Semantic truth.

## The observation-vs-truth law

```text
a provider/tool response is an OBSERVATION, never world-state truth
provider_success = true  does not mean success   (state may still be OBSERVED)
observed                 does not mean verified
verified                 requires a fresh READBACK whose payload matches the intent
uncertain                is a terminal state     (UNKNOWN_EFFECT / PARTIAL_EFFECT)
```

- `effect_record.schema.json` - the `EffectRecord` shape. Closed (`additionalProperties: false`).
  `state` enumerates the full `EFFECT_STATES` list, but the decision law cannot be expressed in
  JSON Schema because it is a transition law, not a shape law: `OBSERVED -> RECONCILED` is not a
  legal edge (`OBSERVED -> READBACK -> RECONCILED` is the only route to truth), a stale readback
  or one that does not match the intent fails closed into `UNKNOWN_EFFECT`, and a denied
  permission reaches `DENIED` with no attempt recorded. Those laws are enforced in
  `src/effect/state.py` and `src/effect/substrate.py`.
