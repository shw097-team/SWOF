"""Entitlement scope, credential scope and the HumanGate route.

WHY: an expired grant is still a grant, and a caller approving its own high-risk action looks
exactly like a normal approval in a log. This module makes expiry/revocation/unknown-entitlement
a typed deny, binds every decision to the scope subject so a grant for one subject cannot be
spent by another, routes high-risk actions through `ARTIFACT:HUMAN_GATE`, and refuses
self-approval. The gate is a refusal mechanism, not an authority grant.

W2 repair WO-SWOF-W2-R001 (F-W2-EXT-001): currentness is now a REQUIRED decision input. A scope
that carries an `expires_at` cannot be evaluated without a trusted `now`; an omitted or malformed
`now` is unknown currentness and fails closed (`CURRENTNESS_UNAVAILABLE_FAIL_CLOSED`). The library
never reads the wall clock, and equality at the expiry instant counts as expired.

W2 repair WO-SWOF-W2-R001 (F-W2-EXT-002): `assert_human_gate_satisfied` no longer accepts a
syntactic string. A gated route requires a typed, exact-bound `ApprovalToken` verified by
`src/security/humangate.py`; every bare string is refused with `NOT_A_CANONICAL_APPROVAL_TOKEN`.

W2 repair WO-SWOF-W2-R002 (BLK-3): the route is re-derived, never trusted. A `required=False`
route is only honoured when an `ApprovalRequest` is supplied and `human_gate_route` agrees; a
route that understates (or overstates) the action raises `ROUTE_UNDERSTATES_ACTION`, and an
underivable route raises `ROUTE_NOT_REDERIVABLE_FAIL_CLOSED`. A P3/P4/P5 action without a valid
typed token surfaces the canonical `DENY_P3_TOKEN_REQUIRED` (TOK-INV-001).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .humangate import (
    ApprovalDecision, ApprovalRequest, ApprovalToken, NonceLedger, VerificationContext,
    verify_approval_token,
)

HIGH_RISK_ACTIONS = frozenset({
    "live_world_effect", "credential_access", "release", "production_promotion",
    "remote_merge", "destructive_scope_expansion", "constitution_change",
})

HUMAN_GATE_ROUTE = "ARTIFACT:HUMAN_GATE"
NONE_ROUTE = "NONE"

# The effect-risk / permission tiers that require a typed approval token (TOK-INV-001).
_APPROVAL_REQUIRED_TIERS = frozenset({"P3", "P4", "P5"})

_AUTHORITY_EDGE = {
    "live_world_effect": "HUMAN_GATE:live_world_effect",
    "credential_access": "HUMAN_GATE:credential_access",
    "release": "HUMAN_GATE:release",
    "production_promotion": "HUMAN_GATE:production_promotion",
    "remote_merge": "HUMAN_GATE:remote_merge",
    "destructive_scope_expansion": "HUMAN_GATE:destructive_scope_expansion",
    "constitution_change": "HUMAN_GATE:constitution_change",
}

_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


class RightsDenied(Exception):
    """The scope does not entitle the subject to the requested use."""

    code = "ERR_RIGHTS_DENIED"


class HumanGateBypassAttempt(Exception):
    """A high-risk action was attempted without a valid, independent approval."""

    code = "ERR_HUMAN_GATE_BYPASS_ATTEMPT"


@dataclass(frozen=True)
class RightsScope:
    """A subject's entitlements. `expires_at` is ISO-8601 UTC; None means no expiry."""

    subject: str
    entitlements: frozenset[str]
    credential_scope: frozenset[str] = field(default_factory=frozenset)
    expires_at: str | None = None
    revoked: bool = False


@dataclass(frozen=True)
class RightsDecision:
    """Entitlement outcome. `allowed` is the only field to trust."""

    allowed: bool
    reason: str
    requires_human_gate: bool


@dataclass(frozen=True)
class HumanGateRoute:
    """Whether an action needs a human gate and which authority edge owns it."""

    required: bool
    route: str
    authority_edge: str


def _scope_valid(scope):
    if not isinstance(scope, RightsScope):
        return "UNKNOWN_SCOPE_FAIL_CLOSED"
    if not isinstance(scope.subject, str) or not scope.subject:
        return "SUBJECT_INVALID_FAIL_CLOSED"
    if not isinstance(scope.entitlements, frozenset):
        return "ENTITLEMENTS_INVALID_FAIL_CLOSED"
    if not isinstance(scope.credential_scope, frozenset):
        return "CREDENTIAL_SCOPE_INVALID_FAIL_CLOSED"
    return None


def _expired(scope, now):
    """Fail closed on unknown expiry or unknown currentness.

    expires is None -> False (nothing to evaluate). A malformed expiry, an omitted or malformed
    `now`, or `now` at/after the expiry instant all read as expired. Reading the wall clock is
    never permitted here: currentness is an explicit trusted input.
    """
    expires = scope.expires_at
    if expires is None:
        return False
    if not isinstance(expires, str) or not _ISO_UTC_RE.match(expires):
        return True
    if now is None:
        return True
    if not isinstance(now, str) or not _ISO_UTC_RE.match(now):
        return True
    return now >= expires


def currentness_required(scope) -> bool:
    """True when the scope carries an expiry, i.e. a trusted `now` must be supplied."""
    return scope.expires_at is not None


def check_rights(scope, entitlement, *, now=None, subject=None) -> RightsDecision:
    """Expired, revoked, unknown, mismatched or malformed entitlements all DENY.

    A scope with an `expires_at` can only be evaluated against a trusted `now`; omitting it is
    unknown currentness and fails closed. A scope with no expiry has nothing to evaluate and is
    still ENTITLED - that positive control must not regress.
    """
    invalid = _scope_valid(scope)
    if invalid is not None:
        return RightsDecision(False, invalid, False)
    if subject is not None and subject != scope.subject:
        return RightsDecision(False, "SUBJECT_MISMATCH", False)
    if not isinstance(entitlement, str) or not entitlement:
        return RightsDecision(False, "ENTITLEMENT_INVALID_FAIL_CLOSED", False)
    if scope.revoked:
        return RightsDecision(False, "REVOKED", False)
    if scope.expires_at is not None and now is None:
        return RightsDecision(False, "CURRENTNESS_UNAVAILABLE_FAIL_CLOSED", False)
    if _expired(scope, now):
        return RightsDecision(False, "EXPIRED", False)
    if entitlement not in scope.entitlements:
        return RightsDecision(False, "UNKNOWN_ENTITLEMENT_FAIL_CLOSED", False)
    gate = entitlement in HIGH_RISK_ACTIONS
    return RightsDecision(True, "ENTITLED", gate)


def human_gate_route(action, *, risk="LOW") -> HumanGateRoute:
    """Every high-risk action is gated on a human artifact; unknown actions are gated too."""
    if not isinstance(action, str) or not action:
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, "HUMAN_GATE:unknown_action")
    if action in HIGH_RISK_ACTIONS:
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, _AUTHORITY_EDGE[action])
    return HumanGateRoute(False, NONE_ROUTE, "NONE")


def assert_credential_scope(scope, use, *, subject=None, now=None) -> None:
    """An empty credential scope permits no credential use; unknown use is denied.

    Currentness is a required input for an expiring credential scope: an omitted `now` raises
    CURRENTNESS_UNAVAILABLE_FAIL_CLOSED and an expired scope raises EXPIRED_CREDENTIAL_SCOPE.
    """
    invalid = _scope_valid(scope)
    if invalid is not None:
        raise RightsDenied(invalid)
    if subject is not None and subject != scope.subject:
        raise RightsDenied("SUBJECT_MISMATCH")
    if not isinstance(use, str) or not use:
        raise RightsDenied("CREDENTIAL_USE_INVALID_FAIL_CLOSED")
    if scope.revoked:
        raise RightsDenied("REVOKED")
    if scope.expires_at is not None and now is None:
        raise RightsDenied("CURRENTNESS_UNAVAILABLE_FAIL_CLOSED")
    if _expired(scope, now):
        raise RightsDenied("EXPIRED_CREDENTIAL_SCOPE")
    if use not in scope.credential_scope:
        raise RightsDenied("CREDENTIAL_USE_OUT_OF_SCOPE: %s" % use)


def assert_human_gate_satisfied(route, approval, *, requesting_actor=None,
                                request=None, ctx=None) -> None:
    """Refuse a missing, self-issued or non-exact-bound approval for a gated route.

    The route is re-derived, never trusted. A `required=False` route is only honoured when an
    `ApprovalRequest` is supplied and `human_gate_route(request.operation)` agrees the action is
    ungated; otherwise the route understates the action (`ROUTE_UNDERSTATES_ACTION`) or cannot be
    re-derived (`ROUTE_NOT_REDERIVABLE_FAIL_CLOSED`). A gated route requires a typed, exact-bound
    `ApprovalToken` plus the `ApprovalRequest` it is bound to and a `VerificationContext` carrying
    trusted currentness. Any bare string, mapping or absent object is refused: a syntactic string
    is not an approval. For a P3/P4/P5 action the refusal of a non-token is the canonical
    `DENY_P3_TOKEN_REQUIRED`.
    """
    if not isinstance(route, HumanGateRoute):
        raise HumanGateBypassAttempt("UNKNOWN_ROUTE_FAIL_CLOSED")
    if request is not None:
        derived = human_gate_route(getattr(request, "operation", None))
        if derived.required and not route.required:
            raise HumanGateBypassAttempt("ROUTE_UNDERSTATES_ACTION")
        if derived.required != route.required:
            raise HumanGateBypassAttempt("ROUTE_UNDERSTATES_ACTION")
    if not route.required:
        if request is None:
            raise HumanGateBypassAttempt("ROUTE_NOT_REDERIVABLE_FAIL_CLOSED")
        return
    if not isinstance(approval, ApprovalToken) or request is None or ctx is None:
        if request is not None and _requires_typed_token(request):
            raise HumanGateBypassAttempt("DENY_P3_TOKEN_REQUIRED")
        raise HumanGateBypassAttempt("NOT_A_CANONICAL_APPROVAL_TOKEN")
    decision = verify_approval_token(approval, request, ctx)
    if not decision.ok:
        raise HumanGateBypassAttempt(decision.code)
    if isinstance(requesting_actor, str) and requesting_actor.strip():
        if approval.approver.strip() == requesting_actor.strip():
            raise HumanGateBypassAttempt("SELF_APPROVAL_REFUSED")
    return None


def _requires_typed_token(request) -> bool:
    """True when the request risk tier or permission class demands a typed approval token."""
    tier = getattr(request, "effect_risk_tier", "")
    permission = getattr(request, "permission_class", "")
    return tier in _APPROVAL_REQUIRED_TIERS or permission in _APPROVAL_REQUIRED_TIERS


__all__ = [
    "HIGH_RISK_ACTIONS", "HUMAN_GATE_ROUTE", "NONE_ROUTE", "ApprovalDecision",
    "ApprovalRequest", "ApprovalToken", "HumanGateBypassAttempt", "HumanGateRoute",
    "NonceLedger", "RightsDecision", "RightsDenied", "RightsScope", "VerificationContext",
    "assert_credential_scope", "assert_human_gate_satisfied", "check_rights",
    "currentness_required", "human_gate_route", "verify_approval_token",
]