# SWOF W2 R9 — Final Evidence Dossier

```yaml
repair_id: SWOF-W2-R9-PI06-POLICY-PROJECTION-BOUNDARY
changeset: NARROW_REPAIR
parent_source_sha: be655b0cd0fe3d77922ab85c3aa5d6b141c7e79e
source_candidate_sha: 0ab90c6582d80056d75e073bf7c861464ea3e2bd
claim_ceiling: READY_FOR_W2_R9_EXTERNAL_RECHALLENGE
```

## Result

R9 preserves canonical PI06 action identity, removes the R8 generic `ACT-T3-HUMAN` collapse, adds the ACT-MERGE HA1+HA3 floor, gives stateful writes a distinct HIGH floor, and returns `TEMP_CLOSED_POLICY_RESOLUTION` where data/resource/domain owner context is required but unavailable.

## Deterministic evidence

- ACT-MERGE with HA1 only: authority-floor denial.
- ACT-MERGE with HA1+HA3: policy floor passes.
- Stateful external write at MEDIUM: risk/authn denial.
- Identity-rights at HIGH: risk-floor denial.
- Data export, financial, physical: owner-boundary temporary closure.
- Irreversible delete at HIGH: critical risk-floor denial.
- Benign local read: no floor error.
- R8 release/secret/reversible-write behavior retained.

## Regression

W1=113, W2=830 (security=468), grand=943, zero denominator roots=0. R8 baseline grand=926; no shrink.

## Claims and nonclaims

This dossier is a candidate handoff only. It does not claim external acceptance, W2 acceptance, W3 implementation, merge, release, production, or world-effect acceptance.
