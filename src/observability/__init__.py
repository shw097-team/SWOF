"""SWOF observability / correlation / redaction / hooks / recovery substrate (W2, WO-SWOF-W2-004).

The other W2 substrates DECIDE (security), TRACK EFFECT (effect) and ASSESS (assurance). This
package is the witness layer: it is the place where a decision, an effect observation, a first
failure, a recovery or an evidence invalidation is RECORDED so that an independent party can
replay what happened without trusting the reporter.

It is deliberately NOT a metrics/tracing/SRE/FinOps platform. It is the minimal set of hooks
needed to PROVE the W2 security/effect/assurance behaviour, and it carries the least authority
in the repository: a log line is an observation, never evidence of world-state success, and
nothing here grants authority or raises a claim ceiling. See README.md for the per-module
contract.

Dependency: `redaction.py` imports `security.classification` (W2-001) explicitly, because the
redaction decision must be the SAME decision the evidence gate makes. A locally re-implemented
detector would be a second source of truth about what a secret is.
"""

__all__ = ["correlation", "redaction", "hooks", "recovery"]