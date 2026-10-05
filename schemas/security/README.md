# Security schemas (W2, WO-SWOF-W2-001)

Machine-checkable projections of the security guards in `src/security/`. A schema is a shape
check only: passing it is not an acceptance, and it never acquires Product or Semantic truth.

- `permission_envelope.schema.json` - the `PermissionEnvelope` shape. Closed
  (`additionalProperties: false`). The law "explicit deny beats allow, unknown action fails
  closed" cannot be expressed in JSON Schema because it is a decision law, not a shape law, so
  it is documented here and enforced in `src/security/permissions.py`.
- `security_veto.schema.json` - the `VetoDecision` shape. A proxy can never clear a veto; that
  is enforced in `src/security/veto.py`.
