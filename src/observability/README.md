# Observability / correlation / redaction / hooks / recovery substrate (W2, WO-SWOF-W2-004)

The witness layer. The other W2 substrates DECIDE (security), TRACK EFFECT (effect) and ASSESS
(assurance); this one RECORDS what happened so an independent party can replay it without
trusting the reporter. It is deliberately NOT a metrics/tracing/SRE/FinOps platform - it is the
minimal set of hooks needed to PROVE the W2 security/effect/assurance behaviour. W4's
SRE/FinOps/research/value program is explicitly out of scope here.

## Truth separation (do not blur these)

```text
event emitted    != event true
log line         != evidence of world-state success
redacted         != safe-to-publish        (PUBLIC text may still be an opinion)
correlation key  != authority
replayable       != accepted
first failure    is EVIDENCE; recovery does not erase it
```

Nothing here grants authority, raises a claim ceiling, or constitutes acceptance. A log line is
an observation produced by the thing under observation, so it can never close a gate.

## Design law

```text
an unknown event kind fails closed           (an untyped event cannot be replayed)
seq is assigned by the bus, contiguous from 1 (a caller cannot forge ordering)
every payload is redacted BEFORE it is stored (a secret never enters the stream)
the FIRST first_failure is retained forever   (recovery must not erase evidence)
an unmapped failure kind has NO recovery path (no silently invented default)
```

## Modules and the failure mode each one prevents

- `correlation.py` - the five-part identity `(trace_id, workorder_id, checkpoint_id,
  subject_id, subject_sha)` every event is bound to. Prevents an unbound (unreplayable) event
  and prevents a derived span from re-pointing the SUBJECT: `derive` takes no subject parameter,
  so an event emitted in one subject's span cannot become another subject's evidence.
  `assert_bound` refuses a blank or non-string field with `ERR_CORRELATION_UNBOUND`; `key` is a
  stable digest over all five fields.
- `redaction.py` - security-safe logging. Builds on `security.classification` (W2-001) so the
  log decision and the evidence decision are the SAME decision. A classified SECRET or PII is
  removed and reported in the receipt; a payload that still carries a SECRET after redaction (a
  secret in a dict KEY, or an unscannable value) raises `LogUnsafe` (`ERR_LOG_UNSAFE`). The gate
  is deliberately NOT satisfiable by an empty string or an empty payload.
- `hooks.py` - the ordered, redacting `HookBus`. Fail-closed closed vocabulary
  (`EVENT_KINDS`), bus-assigned contiguous `seq`, redaction-before-storage with the receipt
  recorded under `_redaction`, first-failure retention, byte-stable `replay()`, and a sink that
  receives ONLY the redacted line.
- `recovery.py` - recovery / rollback hooks. `recovery_plan` maps a failure kind to a registered
  action and RAISES `NoRecoveryPath` (`ERR_NO_RECOVERY_PATH`) for an unmapped kind rather than
  returning a default; every plan carries the `rollback_pointer` bound to the WorkOrder id and
  the baseline SHA. `first_failing_invariant` reads the invariant named by the earliest
  `first_failure`. `deterministic_readback` is a pure function of the events.

## Dependency on W2-001

`redaction.py` imports `security.classification` explicitly (WO-SWOF-W2-001 landed first). This
is deliberate: the log sink is exactly where a secret leaks, so it must use the repository's one
classification decision rather than a second, possibly weaker, detector.

## Running the tests

```text
python -m unittest discover -s src/observability/tests -t src/observability/tests
```

Python 3.11+, standard library only. No network, no sleeps, no wall-clock in a decision, no
filesystem reads at import time. Deterministic ordering everywhere.

## Explicit non-claims

- This is an observation layer, not an authority layer: it never owns Product or Semantic Truth.
- A redacted line is not an acceptance, and a green replay is not evidence of world-state success.
- W2 performs no live effect; fixtures are local/simulated only.