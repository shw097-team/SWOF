# Fabric seam (W1-001)

The provider-neutral narrow waist of PI-PKG-04 §6.1:

```text
Sovereign Semantic World / Canonical Plan IR  (read-only projection)
  -> Mission / TaskSpec / WorkOrder -> ECPDesignSchema -> CapabilityContract
  -> HarnessABI -> {ProviderBindingRef, ToolPermissionContract}
  -> {ProviderProfile, SkillContract} -> InteropProfile -> Provider/Agent Runtime Adapter
```

Upstream writes only SWOF-owned objects; provider-specific fields are quarantined in
`ProviderProfile` / `ProviderBindingRef` / the adapter. Returned events are execution
observation, never semantic truth or acceptance (invariants 4 and 10).

`CapabilityContract` states *what* capability is required and under what constraints;
`provider_binding_ref` is optional and late-bound.
