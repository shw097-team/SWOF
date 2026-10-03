"""SWOF effect / observation / UNKNOWN_EFFECT / reconciliation substrate (W2, WO-SWOF-W2-002).

A STATE MACHINE over immutable effect records, never an executor: nothing in this package
performs a network call, a subprocess, a filesystem effect or a broker/business action. A
provider response is an OBSERVATION, never world-state truth; only a fresh readback that matches
the intended effect may reach RECONCILED, and uncertainty is a first-class terminal state
(UNKNOWN_EFFECT / PARTIAL_EFFECT). See README.md for the contract per module.
"""
