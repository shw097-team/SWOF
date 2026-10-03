"""Entitlement scope, credential scope and the HumanGate route.

WHY: an expired grant is still a grant, and a caller approving its own high-risk action looks
exactly like a normal approval in a log. This module makes expiry/revocation/unknown-entitlement
a typed deny, binds every decision to the scope subject so a grant for one subject cannot be
spent by another, routes high-risk actions through `ARTIFACT:HUMAN_GATE`, and refuses
self-approval. The gate is a refusal mechanism, not an authority grant.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

HIGH_RISK_ACTIONS = frozenset({
    "live_world_effect", "credential_access", "release", "production_promotion",
    "remote_merge", "destructive_scope_expansion", "constitution_change",
})

HUMAN_GATE_ROUTE = "ARTIFACT:HUMAN_GATE"
NONE_ROUTE = "NONE"

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
    expires = scope.expires_at
    if expires is None:
        return False
    if not isinstance(expires, str) or not _ISO_UTC_RE.match(expires):
        return True
    if now is None:
        return False
    if not isinstance(now, str) or not _ISO_UTC_RE.match(now):
        return True
    return now >= expires


def check_rights(scope, entitlement, *, now=None, subject=None) -> RightsDecision:
    """Expired, revoked, unknown, mismatched or malformed entitlements all DENY."""
    invalid = _scope_valid(scope)
    if invalid is not None:
        return RightsDecision(False, invalid, False)
    if subject is not None and subject != scope.subject:
        return RightsDecision(False, "SUBJECT_MISMATCH", False)
    if not isinstance(entitlement, str) or not entitlement:
        return RightsDecision(False, "ENTITLEMENT_INVALID_FAIL_CLOSED", False)
    if scope.revoked:
        return RightsDecision(False, "REVOKED", False)
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


def assert_human_gate_satisfied(route, approval_ref, *, requesting_actor=None) -> None:
    """Refuse a missing, self-issued or malformed approval for a gated route."""
    if not isinstance(route, HumanGateRoute):
        raise HumanGateBypassAttempt("UNKNOWN_ROUTE_FAIL_CLOSED")
    if not route.required:
        return
    if not isinstance(approval_ref, str) or not approval_ref.strip():
        raise HumanGateBypassAttempt(
            "route %s requires an approval reference (%s)" % (route.route, route.authority_edge))
    if requesting_actor is not None:
        if not isinstance(requesting_actor, str) or not requesting_actor.strip():
            raise HumanGateBypassAttempt("requesting_actor is ambiguous; refusing approval")
        if approval_ref.strip() == requesting_actor.strip():
            raise HumanGateBypassAttempt(
                "approval reference equals the requesting actor: self-approval refused")


def assert_credential_scope(scope, use, *, subject=None) -> None:
    """An empty credential scope permits no credential use; unknown use is denied."""
    invalid = _scope_valid(scope)
    if invalid is not None:
        raise RightsDenied(invalid)
    if subject is not None and subject != scope.subject:
        raise RightsDenied("SUBJECT_MISMATCH")
    if not isinstance(use, str) or not use:
        raise RightsDenied("CREDENTIAL_USE_INVALID_FAIL_CLOSED")
    if scope.revoked:
        raise RightsDenied("REVOKED")
    if use not in scope.credential_scope:
        raise RightsDenied("CREDENTIAL_USE_OUT_OF_SCOPE: %s" % use)
