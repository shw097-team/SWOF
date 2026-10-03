# Effect / observation / UNKNOWN_EFFECT / reconciliation substrate (W2, WO-SWOF-W2-002)

A STATE MACHINE over immutable effect records. It is **not an executor**: no module here makes a
network call, starts a subprocess, performs a filesystem effect, or takes a broker/business
action. Every function works on local/simulated fixtures and returns a new record.

## The law this seam enforces

```text
provider response        != world-state truth
provider_success = true  != RECONCILED
observed                 != verified
green execution          != acceptance
uncertain                != error        (UNKNOWN_EFFECT is a terminal state)
retry                    != readback
```

## Modules and the failure mode each one prevents

- `state.py` - the closed alphabet of effect states and the legal edges between them. Prevents an
  invented state (unknown names are refused) and, crucially, prevents `OBSERVED -> RECONCILED`:
  the only route to truth is `OBSERVED -> READBACK -> RECONCILED`. `DENIED` is reachable only from
  `INTENDED`, and a terminal state rejects all further transitions except
  `PARTIAL_EFFECT -> COMPENSATED`.
- `substrate.py` - the record state machine. `intend` freezes an immutable intent digest;
  `record_attempt` DENIES (recording no attempt) when permission is refused, and accepts a fresh
  attempt (a new attempt_key) ONLY from `INTENDED` and `UNKNOWN_EFFECT` - the states where no
  effect is known to have been applied. From `PARTIAL_EFFECT`, `OBSERVED`, `READBACK`, `DENIED`,
  `RECONCILED` or `IRREVERSIBLE` a fresh attempt is REFUSED with a typed `FreshAttemptRefused`
  (and a specific `reason_code`, e.g. `FRESH_ATTEMPT_REFUSED_PARTIAL_EFFECT`), so a partly-applied
  or already-observed effect cannot be re-armed by a new side effect; duplicate-key detection
  still fires first. `observe` records a provider OBSERVATION and moves `ATTEMPTED -> OBSERVED`
  but never to success; `readback` records evidence about the world (and refuses evidence about
  another subject); `reconcile` decides the terminal state from readbacks alone; `finalize` is
  the fail-closed sweep that turns any unresolved record into `UNKNOWN_EFFECT` - including a
  mid-flight record, which is the documented route to making it retryable;
  `assert_no_success_inference` raises unless the record is `RECONCILED`; `is_success` is True
  only for `RECONCILED`.
- `idempotency.py` - one attempt key per intended effect (`sha256` over the immutable identity),
  plus a hard retry ceiling. Prevents a retry from becoming a duplicate side effect and refuses
  retries of `RECONCILED` / `DENIED` / `IRREVERSIBLE` effects. A retry is allowed ONLY from
  `UNKNOWN_EFFECT` (nothing has been confirmed applied): a MID-FLIGHT state (`ATTEMPTED` /
  `OBSERVED` / `READBACK`) is refused as `RETRY_REFUSED_MID_FLIGHT`, and `PARTIAL_EFFECT` is NOT
  retryable (`RETRY_REFUSED_PARTIAL_EFFECT`) with a fresh READBACK plus the compensation pointer
  as its recovery route, never another side effect. The documented path out of a mid-flight
  record is `finalize()` (which normalises it to `UNKNOWN_EFFECT`) and then a retry, or a
  re-observe.
- `compensation.py` - reversibility classification and compensation PLANNING (never execution).
  An irreversible effect yields a non-compensable pointer whose `assert_compensable` raises; a
  `PARTIAL_EFFECT` with no registered path is refused with `NoCompensationPath`.
- `correlation.py` - the four-part effect/evidence identity (effect, subject, intent digest,
  environment). Prevents evidence about another subject (`WrongSubjectEvidence`) or another effect
  (`CorrelationMismatch`) from being bound to this one.

## Terminal states

`RECONCILED` is the only success. `UNKNOWN_EFFECT` and `PARTIAL_EFFECT` are first-class terminal
states reached when truth cannot be established - they are not errors to be retried away. Only
`UNKNOWN_EFFECT` may be retried; `PARTIAL_EFFECT` has already applied part of the intent, so its
recovery is a fresh readback plus the compensation pointer. `DENIED`, `FAILED`, `COMPENSATED` and
`IRREVERSIBLE` are likewise terminal.

## Running the tests

```text
python -m unittest discover -s src/effect/tests -t src/effect/tests
```

Python 3.11+, standard library only. Deterministic: every function accepts an injected `at`.
