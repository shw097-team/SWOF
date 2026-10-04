# Observability schemas (W2, WO-SWOF-W2-004)

Shape projections of the observability substrate in `src/observability/`. A shape check is not an
acceptance, and a shape never acquires Product or Semantic truth. The ordering, redaction and
first-failure laws are enforced in Python, because they are laws about a stream rather than
shapes.

This directory documents the projected shapes. Unlike `schemas/security/`, `schemas/effect/` and
`schemas/assurance/`, this write-set ships no `.schema.json` file: every observability law here
is a STREAM law (bus-assigned ordering, redact-before-store, first-failure retention) that a
closed JSON shape cannot express without pretending to enforce it. Shipping a schema that cannot
enforce its own law would be a proxy, so the laws live only in Python and are proven by the
adversarial tests.

## Projected shapes

```text
correlation context - the five-part identity every event is bound to
    trace_id, workorder_id, checkpoint_id, subject_id, subject_sha: all NON-EMPTY strings
    derive() may move the trace but can NEVER re-point subject_id / subject_sha
    (blank or non-string field => ERR_CORRELATION_UNBOUND, enforced in correlation.py)

event               - one hooked occurrence
    seq: integer >= 1, contiguous, assigned by the bus (a caller cannot choose it)
    kind: one of EVENT_KINDS (trace_start, workorder_state, checkpoint, first_failure,
          recovery, rollback, evidence_invalidation, subject_bound)
    correlation: a bound correlation context
    payload: an object that was REDACTED before storage; it carries a `_redaction` receipt
    emitted_at: a string timestamp
    (unknown kind => ERR_UNKNOWN_EVENT_KIND; a non-redacted secret => ERR_LOG_UNSAFE)

first failure       - the earliest first_failure event is retained forever; a later recovery
    does not erase it, because a first failure is evidence

recovery plan       - failure_kind -> registered action, ALWAYS with a rollback pointer bound
    to the workorder id and the baseline SHA; an unmapped kind => ERR_NO_RECOVERY_PATH,
    never an invented default
```

## Explicit non-claims

- A shape pass is not an acceptance, and a stored event is not evidence of world-state success.
- The observability layer is an observation layer: it never owns Product or Semantic Truth and
  never becomes a second semantic root.
- It is NOT an SRE/FinOps/tracing/metrics platform; W4 owns that program.
- A secret is removed before storage, but a redacted line is still an observation, not a
  judgement.