"""SWOF security / privacy / rights / HumanGate substrate (W2, WO-SWOF-W2-001).

Fail-closed guards that refuse; they never grant authority and never become a source of
Product, Semantic or Acceptance truth. See README.md for the contract per module.

WO-SWOF-W2-R001 adds the typed HumanGate approval surface (`humangate.py`): exact-bound
`ApprovalToken` value objects verified by an injected trusted key registry, plus rights
currentness (`currentness_required`) that fails closed when a trusted `now` is unavailable.
"""
from .humangate import (  # noqa: F401
    AUTHN_ASSURANCE_CLASSES, INTEGRITY_PROFILE_ID, TOKEN_STATES, ApprovalDecision,
    ApprovalRequest, ApprovalToken, NonceLedger, VerificationContext, verify_approval_token,
)
from .rights import (  # noqa: F401
    HIGH_RISK_ACTIONS, HUMAN_GATE_ROUTE, NONE_ROUTE, HumanGateBypassAttempt, HumanGateRoute,
    RightsDecision, RightsDenied, RightsScope, assert_credential_scope,
    assert_human_gate_satisfied, check_rights, currentness_required, human_gate_route,
)

__all__ = [
    "AUTHN_ASSURANCE_CLASSES", "HIGH_RISK_ACTIONS", "HUMAN_GATE_ROUTE", "INTEGRITY_PROFILE_ID",
    "NONE_ROUTE", "TOKEN_STATES", "ApprovalDecision", "ApprovalRequest", "ApprovalToken",
    "HumanGateBypassAttempt", "HumanGateRoute", "NonceLedger", "RightsDecision", "RightsDenied",
    "RightsScope", "VerificationContext", "assert_credential_scope",
    "assert_human_gate_satisfied", "check_rights", "currentness_required", "human_gate_route",
    "verify_approval_token",
]