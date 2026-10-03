# Security / privacy / rights / HumanGate substrate (W2, WO-SWOF-W2-001)

Fail-closed guards for least privilege, content provenance, injection quarantine, secret
classification, entitlement scope, dependency identity and the security veto.

## The law this seam enforces

```text
external content != instruction
not-denied        != allowed
green proxy       != security evidence
expired/revoked   != entitled
unpinned          != admissible
```

Every guard here REFUSES. None of them grants authority, raises a claim ceiling, produces
Product/Semantic truth, or constitutes acceptance: a module that cannot say NO is a defect.

## Modules and the failure mode each one prevents

- `permissions.py` - least privilege. Prevents "not denied therefore allowed" and self-service
  `widen`; explicit deny beats allow, unknown actions fail closed (`UNKNOWN_ACTION_FAIL_CLOSED`),
  and human-gated actions are never directly usable.
- `provenance.py` - content provenance. Prevents a retrieved document or model output from
  promoting itself into an INSTRUCTION; only a registered-authority owner may promote, and that
  promotion is an authority edge.
- `injection.py` - prompt/tool injection. Prevents hostile text and poisoned tool output from
  being obeyed; quarantine never raises on hostile input, and `detector_selftest` proves every
  detector can actually fail.
- `classification.py` - secret/PII handling. Prevents a credential from reaching evidence;
  `assert_no_secret` is a hard gate that an empty payload cannot satisfy.
- `rights.py` - entitlement scope and the HumanGate route. Prevents expired/revoked/unknown-
  entitlement use, cross-subject borrowing, self-approval and out-of-scope credential use.
- `supplychain.py` - dependency identity. Prevents a hash-mismatched, unpinned or unknown-licence
  artifact from being admitted; it reads only registered metadata and never the network.
- `veto.py` - security veto. Prevents success proxies (test-green, CI-green, LLM-judge score)
  from clearing a security veto, and fails closed on unknown or ambiguous signals.

## Running the tests

```text
python -m unittest discover -s src/security/tests -t src/security/tests
```

Python 3.11+, standard library only. No network, no sleeps, no filesystem reads at import time.
