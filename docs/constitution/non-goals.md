# Non-goals (current boundary: through W2)

Explicit from the construction order and PI-PKG-00 Sec. 1.4:

- No second RBWI, second compiler, second orchestrator, second task DB, second semantic root or
  parallel canonical writer. `canonical_plan_ir_count = 1` holds for every wave.
- No mutation of the source corpus, of HG-KSEOS source/config, or of Fabric canonical contracts.
  `src/observability/` reads and writes nothing outside this repository.
- No provider becomes semantic authority; runtime/provider state stays replaceable and is never
  Semantic Truth. A provider response is an observation.
- No external acceptance, release, production or unqualified world-effect claim from this root.
  Local green is not acceptance, and an accepted baseline verdict does not cover W0-W2 work.
- W3-W5 are `PLANNED_NOT_DISPATCHED`; nothing beyond W2 is implemented here.
- W2 performs NO live effect: its effect, assurance and observability fixtures are
  local/simulated only, and no fixture is a world-effect claim.
- W2 does NOT activate OPA, OpenFGA, Cedar, OpenLineage or any other named provider merely
  because it is named. Naming a technology is not adopting it, and no W2 module requires,
  installs or calls one.
- No credential capture in this repository; a classified SECRET or PII value is redacted before
  it reaches any log sink or evidence payload.