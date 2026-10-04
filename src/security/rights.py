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
route is only honoured when an `ApprovalRequest` is supplied and the predicate agrees; a route
that understates the action raises `ROUTE_UNDERSTATES_ACTION`, and an underivable route raises
`ROUTE_NOT_REDERIVABLE_FAIL_CLOSED`. A P3/P4/P5 action without a valid typed token surfaces the
canonical `DENY_P3_TOKEN_REQUIRED` (TOK-INV-001).

W2 repair WO-SWOF-W2-R004 (R4 D1/D2): there is now ONE canonical gate predicate,
`human_gate_required(request)`. Risk/permission classification is authoritative; the operation
name may TIGHTEN or identify the route but may never WEAKEN it. RUIN / UNKNOWN_RUIN precedence is
evaluated FIRST, before any approval consideration, and a valid token can never satisfy it.

W2 repair WO-SWOF-W2-R005 (R5): RUIN / UNKNOWN_RUIN are carried INSIDE the ONE canonical
EffectRiskTier enum (`effect_risk_tier` = LOW | MEDIUM | HIGH | CRITICAL | RUIN | UNKNOWN_RUIN);
`ruin_class` does NOT exist in the canonical source and is accepted ONLY as a NON-CANONICAL legacy
alias when `effect_risk_tier` is absent, and it may never weaken a present canonical value. A
present-but-malformed `effect_risk_tier` / `permission_class` / `autonomy_tier` fails closed instead
of being treated as ungated (DOC-03 15.6). `human_gate_route` and `human_gate_required` share the ONE
predicate, and `verify_approval_token` returns a typed decision for a malformed nonce ledger.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .humangate import (
    EFFECT_RISK_TIERS, ApprovalDecision, ApprovalRequest, ApprovalToken, NonceLedger,
    VerificationContext, _CLASS_ABSENT, _CLASS_MALFORMED, _CLASS_VALID, classify_autonomy_tier,
    classify_effect_risk_tier, classify_legacy_ruin_class, classify_permission_class,
    ruin_precedence_code, verify_approval_token,
)

HIGH_RISK_ACTIONS = frozenset({
    "live_world_effect", "credential_access", "release", "production_promotion",
    "remote_merge", "destructive_scope_expansion", "constitution_change",
})

HUMAN_GATE_ROUTE = "ARTIFACT:HUMAN_GATE"
RUIN_HARD_VETO_ROUTE = "ARTIFACT:RUIN_HARD_VETO"
RUIN_SAFE_STOP_ROUTE = "ARTIFACT:RUIN_SAFE_STOP"
NONE_ROUTE = "NONE"

# WO-SWOF-W2-R005 (R5): the token requirement is keyed to the CANONICAL classification domains.
# A token is required by RISK when `effect_risk_tier` is HIGH/CRITICAL/RUIN/UNKNOWN_RUIN (LOW/MEDIUM
# do not by themselves), by PERMISSION floor when `permission_class` is P3/P4/P5 (TOK-INV-001), by
# AUTONOMY when `autonomy_tier` is T3, or when the operation maps to an explicit high-risk edge.
_TOKEN_REQUIRED_RISK_TIERS = frozenset({"HIGH", "CRITICAL", "RUIN", "UNKNOWN_RUIN"})
_TOKEN_REQUIRED_PERMISSION_CLASSES = frozenset({"P3", "P4", "P5"})

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


def human_gate_required(request) -> HumanGateRoute:
    """ONE canonical gate predicate. Risk/permission/autonomy classification is authoritative; the
    operation name may TIGHTEN or identify the route but may NEVER weaken it.

    Order (normative), all fail closed (DOC-03 15.6):

      1. RUIN precedence FIRST, before any approval consideration, DERIVED FROM THE CANONICAL
         `effect_risk_tier` (`ruin_precedence_code`):
           "RUIN"          -> RUIN_HARD_VETO_ROUTE / "RUIN:HARD_VETO"
           "UNKNOWN_RUIN"  -> RUIN_SAFE_STOP_ROUTE / "RUIN:SAFE_STOP"
           a malformed risk tier and a malformed NON-CANONICAL `ruin_class` alias -> SAFE_STOP.
         A token can never satisfy these; the verifier rejects them before checking approval.
      2. a malformed `effect_risk_tier`, `permission_class` or `autonomy_tier` is unclassifiable and
         fails closed (gated, no authority edge); it is NEVER treated as ungated.
      3. token required if ANY of:
           effect_risk_tier in {"HIGH","CRITICAL","RUIN","UNKNOWN_RUIN"}
           permission_class in {"P3","P4","P5"}
           autonomy_tier == "T3"
           the operation maps to an explicit high-risk authority edge
      4. otherwise an ABSENT classification on a NAMED benign operation is the shim's NONE route;
         an EMPTY / non-string operation name is unknown and is gated (`HUMAN_GATE:unknown_action`),
         so the route shim and the predicate agree on the unknown-operation rule.
    """
    ruin = ruin_precedence_code(request)
    if ruin == "HARD_VETO_RUIN":
        return HumanGateRoute(True, RUIN_HARD_VETO_ROUTE, "RUIN:HARD_VETO")
    if ruin == "SAFE_STOP_UNKNOWN_RUIN":
        return HumanGateRoute(True, RUIN_SAFE_STOP_ROUTE, "RUIN:SAFE_STOP")

    risk_state, risk = classify_effect_risk_tier(request)
    permission_state, permission = classify_permission_class(request)
    autonomy_state, autonomy = classify_autonomy_tier(request)
    legacy_state, _ = classify_legacy_ruin_class(request)
    operation = getattr(request, "operation", None)

    # The operation name may TIGHTEN or IDENTIFY the route: a high-risk operation always gates and
    # names its own authority edge, whatever the classification (this can never weaken the law).
    if isinstance(operation, str) and operation in HIGH_RISK_ACTIONS:
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, _AUTHORITY_EDGE[operation])
    # A malformed classification is unclassifiable; it fails closed and is never treated as ungated.
    if _CLASS_MALFORMED in (risk_state, permission_state, autonomy_state, legacy_state):
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, "HUMAN_GATE:unclassified")
    if _CLASS_VALID in (risk_state, permission_state, autonomy_state):
        if risk in _TOKEN_REQUIRED_RISK_TIERS or autonomy == "T3" \
                or permission in _TOKEN_REQUIRED_PERMISSION_CLASSES:
            return HumanGateRoute(True, HUMAN_GATE_ROUTE, _risk_edge(operation))
        # a fully-classified, non-T3, canonical LOW/MEDIUM/P0..P2 action is benign.
        return HumanGateRoute(False, NONE_ROUTE, "NONE")
    # every classification is ABSENT. An EMPTY or non-string operation name is unknown -> gated by
    # the ONE predicate (so human_gate_route("") and human_gate_required(operation="") AGREE).
    # A named, untightened benign action is the shim's NONE route; a classification-carrying caller
    # always reaches the VALID branch above, so this can never weaken a supplied classification.
    if isinstance(operation, str) and operation:
        return HumanGateRoute(False, NONE_ROUTE, "NONE")
    return HumanGateRoute(True, HUMAN_GATE_ROUTE, "HUMAN_GATE:unknown_action")


def _risk_edge(operation) -> str:
    """The authority edge for a classification-gated action; a high-risk op identifies its edge."""
    if isinstance(operation, str) and operation in HIGH_RISK_ACTIONS:
        return _AUTHORITY_EDGE[operation]
    return "HUMAN_GATE:risk_tier"


def human_gate_route(action, *, risk="LOW") -> HumanGateRoute:
    """Action-name shim over the ONE canonical predicate (no second authority path).

    A non-string or empty action is an unknown action and is gated without an authority edge. Any
    other action is classified by `human_gate_required` via a synthetic request whose classification
    is ABSENT, so the operation name can identify or tighten the route but can never weaken the
    risk/permission law. In particular `human_gate_route("")` and `human_gate_required` on a request
    with an empty operation AGREE: an unknown operation is gated by the ONE canonical predicate.
    """
    if not isinstance(action, str) or not action:
        return human_gate_required(ApprovalRequest(operation=""))
    return human_gate_required(ApprovalRequest(operation=action))


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


def _requires_typed_token(request) -> bool:
    """True when a request demands a typed approval token; a malformed/absent classification does.

    A present-but-malformed enum fails closed (True), never a permissive default.
    """
    tier_state, tier = classify_effect_risk_tier(request)
    permission_state, permission = classify_permission_class(request)
    autonomy_state, autonomy = classify_autonomy_tier(request)
    if _CLASS_MALFORMED in (tier_state, permission_state, autonomy_state):
        return True
    return (tier in _TOKEN_REQUIRED_RISK_TIERS
            or permission in _TOKEN_REQUIRED_PERMISSION_CLASSES
            or autonomy == "T3")


def _route_is_ruin(route) -> bool:
    return route.route in (RUIN_HARD_VETO_ROUTE, RUIN_SAFE_STOP_ROUTE)


def assert_human_gate_satisfied(route, approval, *, requesting_actor=None,
                                request=None, ctx=None) -> None:
    """Refuse a missing, self-issued or non-exact-bound approval for a gated route.

    The route is re-derived from the REQUEST via the ONE canonical predicate, never trusted. A
    `required=False` route is only honoured when an `ApprovalRequest` is supplied and the
    predicate agrees the action is ungated; otherwise the route understates the action
    (`ROUTE_UNDERSTATES_ACTION`) or cannot be re-derived (`ROUTE_NOT_REDERIVABLE_FAIL_CLOSED`).

    RUIN / UNKNOWN_RUIN precedence is evaluated FIRST and raises `HARD_VETO_RUIN` /
    `SAFE_STOP_UNKNOWN_RUIN` REGARDLESS of the token, before any token check.

    A gated route requires a typed, exact-bound `ApprovalToken` plus the `ApprovalRequest` it is
    bound to and a `VerificationContext` carrying trusted currentness. Any bare string, mapping or
    absent object is refused: a syntactic string is not an approval. For a P3/P4/P5 action the
    refusal of a non-token is the canonical `DENY_P3_TOKEN_REQUIRED`.
    """
    if not isinstance(route, HumanGateRoute):
        raise HumanGateBypassAttempt("UNKNOWN_ROUTE_FAIL_CLOSED")

    # D2: ruin precedence FIRST, before any approval consideration; a token can never satisfy it.
    if request is not None:
        ruin = _ruin_veto_code(request)
        if ruin is not None:
            raise HumanGateBypassAttempt(ruin)
    if _route_is_ruin(route):
        raise HumanGateBypassAttempt(
            "HARD_VETO_RUIN" if route.route == RUIN_HARD_VETO_ROUTE else "SAFE_STOP_UNKNOWN_RUIN")

    if request is not None:
        derived = human_gate_required(request)
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


def _ruin_veto_code(request):
    """The HARD_VETO/SAFE_STOP code for a request, or None; derived from the canonical field."""
    return ruin_precedence_code(request)


__all__ = [
    "EFFECT_RISK_TIERS", "HIGH_RISK_ACTIONS", "HUMAN_GATE_ROUTE", "NONE_ROUTE",
    "RUIN_HARD_VETO_ROUTE", "RUIN_SAFE_STOP_ROUTE", "ApprovalDecision", "ApprovalRequest",
    "ApprovalToken", "HumanGateBypassAttempt", "HumanGateRoute", "NonceLedger", "RightsDecision",
    "RightsDenied", "RightsScope", "VerificationContext", "assert_credential_scope",
    "assert_human_gate_satisfied", "check_rights", "currentness_required", "human_gate_required",
    "human_gate_route", "verify_approval_token",
]
