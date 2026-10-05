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

W2 repair WO-SWOF-W2-R006 (R6): the OPERATION axis of the gate is now canonical and fails closed.
DOC-03 L867/L874 classify `operation` / `action_class` against a known action enum, and an
unclassifiable operation is an UNKNOWN_RUIN-classed outcome, not a benign one. The predicate
therefore resolves the operation through ONE canonical classifier: a KNOWN benign operation keeps
the classification-driven route, a KNOWN operation that names an authority edge tightens it, and an
UNCLASSIFIABLE operation (unknown name, empty, non-string, or an unestablished canonical value)
returns the SAFE_STOP route. The operation name may tighten the route; it may NEVER weaken it.

W2 repair WO-SWOF-W2-R007 (R7): the trusted route-admission boundary now runs BEFORE any
benign NONE return. When a request is supplied, `assert_human_gate_satisfied` resolves its
CURRENT canonical counterpart through the existing owner-injected `request_resolver` seam and
pins the caller request to it on the policy-owned fields. An absent resolver, an
unresolvable/stale/foreign request, or any caller-declared policy downgrade fails closed
(`DENY_REQUEST_UNRESOLVED` / `DENY_REQUEST_POLICY_MISMATCH`), the RUIN precedence and the
HumanGate route are derived from the TRUSTED request, and the SUPPLIED route must equal the
trusted-derived route on `required`, `route` and `authority_edge`. A caller can therefore no
longer lower every route-driving field to a benign combination and skip the verifier.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .humangate import (
    EFFECT_RISK_TIERS, ApprovalDecision, ApprovalRequest, ApprovalToken, NonceLedger,
    VerificationContext, _CLASS_ABSENT, _CLASS_MALFORMED, _CLASS_VALID, _REQUEST_POLICY_FIELDS,
    _resolve_current_request, classify_autonomy_tier, classify_effect_risk_tier,
    classify_legacy_ruin_class, classify_permission_class, ruin_precedence_code,
    verify_approval_token,
)

HIGH_RISK_ACTIONS = frozenset({
    "live_world_effect", "credential_access", "release", "production_promotion",
    "remote_merge", "destructive_scope_expansion", "constitution_change",
})

HUMAN_GATE_ROUTE = "ARTIFACT:HUMAN_GATE"
RUIN_HARD_VETO_ROUTE = "ARTIFACT:RUIN_HARD_VETO"
RUIN_SAFE_STOP_ROUTE = "ARTIFACT:RUIN_SAFE_STOP"
NONE_ROUTE = "NONE"

# WO-SWOF-W2-R006 (R6): the canonical OPERATION axis (DOC-03 L867 `operation` / L874 `action_class`).
# An operation is classified against the canonical 09.1 ACTION_EFFECT_CLASS_MATRIX names plus the
# benign operation names the accepted control suite already uses, so a known benign action does not
# regress. Anything else - an unrecognised name, an empty or non-string value, or a canonical value
# whose operation vocabulary cannot be established with confidence - is UNCLASSIFIABLE and SAFE-STOPS.
# Over-blocking is the accepted cost; fail-open is not. No benign mapping is guessed here: the set is
# exactly the spec-quoted matrix names, the high-risk actions the gate already names, and `read`,
# the benign action name the accepted tests use.
_OPERATION_CLASS_MATRIX = frozenset({
    "ACT-READ-LOCAL", "ACT-DESIGN-WRITE", "ACT-EXTERNAL-READ", "ACT-EXTERNAL-WRITE-REV",
    "ACT-EXTERNAL-WRITE-STATEFUL", "ACT-DATA-EXPORT", "ACT-SECRET-RESOLVE", "ACT-IDENTITY-RIGHTS",
    "ACT-MERGE", "ACT-DEPLOY-RELEASE", "ACT-FINANCIAL", "ACT-PHYSICAL", "ACT-DELETE-IRREV",
})
_OPERATION_BENIGN = frozenset({"read"})
# R6: the canonical action classes whose EFFECT is consequential. DOC-03 L396-410 classifies on the
# EFFECT, "not on how harmless the prompt text appears", so a request that names one of these classes
# TIGHTENS to a gated route with a class-derived authority edge, however benign its asserted tier is.
# The local read/design classes and the external READ class carry no tightening of their own.
_OPERATION_TIGHTENED = frozenset({
    "ACT-EXTERNAL-WRITE-REV", "ACT-EXTERNAL-WRITE-STATEFUL", "ACT-DATA-EXPORT",
    "ACT-SECRET-RESOLVE", "ACT-IDENTITY-RIGHTS", "ACT-MERGE", "ACT-DEPLOY-RELEASE",
    "ACT-FINANCIAL", "ACT-PHYSICAL", "ACT-DELETE-IRREV",
})
_OPERATION_KNOWN = frozenset(_OPERATION_CLASS_MATRIX | _OPERATION_BENIGN | HIGH_RISK_ACTIONS)


def classify_operation(value):
    """The canonical operation/action classification of a value as a (state, value) pair.

    ABSENT is `None`; VALID is a name in the canonical operation set; everything else - an
    unrecognised name, an empty or blank string, or any non-string - is MALFORMED, which the gate
    treats as unclassifiable and SAFE-STOPS. A caller may extend VALID only by supplying an
    explicit canonical `operation_class`, never by guessing a benign mapping.
    """
    if value is None:
        return (_CLASS_ABSENT, None)
    if isinstance(value, str) and value in _OPERATION_KNOWN:
        return (_CLASS_VALID, value)
    return (_CLASS_MALFORMED, value)


def operation_classes(request):
    """The operation classes a request carries, or None when it is unclassifiable.

    A declaration may only CONFIRM a known operation name. A `operation_class` that is unrecognised,
    empty, or disagrees with the resolved operation is unclassifiable, so the declaration axis can
    never rescue an unknown operation and can never weaken the route.
    """
    state, value = classify_operation(getattr(request, "operation", None))
    if state != _CLASS_VALID:
        # An ABSENT operation is an UNNAMED action, not a benign one: it is unclassifiable and the
        # gate SAFE-STOPS. Only a KNOWN canonical name yields a classification.
        return None
    declared = getattr(request, "operation_class", None)
    if declared is not None and declared != value:
        # A declaration may only confirm the resolved operation; it can never rescue or redirect it.
        return None
    return frozenset({value})

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
      3. the OPERATION axis (R6, DOC-03 L867/L874) is resolved through the ONE canonical
         classifier `classify_operation` / `operation_classes`. An UNCLASSIFIABLE operation is an
         UNKNOWN_RUIN-classed outcome: it SAFE-STOPS (`RUIN_SAFE_STOP_ROUTE` / "RUIN:SAFE_STOP",
         authority edge "RUIN:SAFE_STOP") and is never ungated. A KNOWN operation that maps to an
         explicit high-risk authority edge tightens to that edge; a KNOWN benign operation may only
         keep the route the risk/permission/autonomy classification already decides.
      4. token required if ANY of:
           effect_risk_tier in {"HIGH","CRITICAL","RUIN","UNKNOWN_RUIN"}
           permission_class in {"P3","P4","P5"}
           autonomy_tier == "T3"
           the operation maps to an explicit high-risk authority edge
      5. otherwise a fully-classified, non-T3, canonical LOW/MEDIUM/P0..P2 action on a KNOWN benign
         operation is the predicate's NONE route. The shim and the predicate therefore agree: an
         unknown operation SAFE-STOPS at both entry points, and only a KNOWN benign action is ungated.
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
    classes = operation_classes(request)

    # R6: an UNCLASSIFIABLE operation - an unrecognised name, an empty/blank string, or a non-string
    # - is an UNKNOWN_RUIN-classed outcome and SAFE-STOPS (DOC-03 L867/L874). It is never treated as
    # ungated and can never be the reason a request passes; over-blocking is the accepted cost.
    if classes is None:
        return HumanGateRoute(True, RUIN_SAFE_STOP_ROUTE, "RUIN:SAFE_STOP")
    # The operation name may TIGHTEN or IDENTIFY the route: a high-risk operation always gates and
    # names its own authority edge, whatever the classification (this can never weaken the law).
    if isinstance(operation, str) and operation in HIGH_RISK_ACTIONS:
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, _AUTHORITY_EDGE[operation])
    # R6: a canonical class whose EFFECT is consequential tightens the same way, so a benign-looking
    # asserted tier can never smuggle an irreversible/external effect past the gate.
    if classes & _OPERATION_TIGHTENED:
        edge = sorted(classes & _OPERATION_TIGHTENED)[0]
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, "HUMAN_GATE:%s" % edge)
    # A malformed classification is unclassifiable; it fails closed and is never treated as ungated.
    if _CLASS_MALFORMED in (risk_state, permission_state, autonomy_state, legacy_state):
        return HumanGateRoute(True, HUMAN_GATE_ROUTE, "HUMAN_GATE:unclassified")
    if _CLASS_VALID in (risk_state, permission_state, autonomy_state):
        if risk in _TOKEN_REQUIRED_RISK_TIERS or autonomy == "T3" \
                or permission in _TOKEN_REQUIRED_PERMISSION_CLASSES:
            return HumanGateRoute(True, HUMAN_GATE_ROUTE, _risk_edge(operation))
        # a fully-classified, non-T3, canonical LOW/MEDIUM/P0..P2 action is benign: the operation is
        # KNOWN (an unclassifiable one SAFE-STOPPED above), so this is the positive control.
        return HumanGateRoute(False, NONE_ROUTE, "NONE")
    # every classification is ABSENT and the operation is KNOWN. A KNOWN benign operation keeps the
    # NONE route; a KNOWN operation with no tightening edge is untightened and stays ungated. An
    # unclassifiable operation never reaches here: it SAFE-STOPPED above.
    return HumanGateRoute(False, NONE_ROUTE, "NONE")


def _risk_edge(operation) -> str:
    """The authority edge for a classification-gated action; a high-risk op identifies its edge.

    R6: only a KNOWN operation reaches a classification-gated edge with its own name; an unclassifiable
    operation has already SAFE-STOPPED in the ONE predicate and never arrives here.
    """
    if isinstance(operation, str) and operation in HIGH_RISK_ACTIONS:
        return _AUTHORITY_EDGE[operation]
    return "HUMAN_GATE:risk_tier"


def human_gate_route(action, *, risk="LOW") -> HumanGateRoute:
    """Action-name shim over the ONE canonical predicate (no second authority path).

    A non-string or empty action is unknown and SAFE-STOPS (`RUIN_SAFE_STOP`). Any other action is
    resolved by `human_gate_required` via a synthetic request whose classification is ABSENT, so the
    name can identify or tighten the route but can never weaken the risk/permission law. R6: the shim
    defers the whole operation/classification judgement to the ONE canonical predicate - including
    the unknown-operation rule - so every entry point AGREE by construction, and a non-string action
    is fed through as-is rather than coerced into a string that could name a known action.
    """
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

    The route is re-derived from a TRUSTED request via the ONE canonical predicate, never trusted.
    A `required=False` route is only honoured when an `ApprovalRequest` is supplied, its CURRENT
    canonical counterpart resolves through the owner-injected `request_resolver` seam, and the
    predicate agrees on `required`, `route` and `authority_edge`; otherwise the route understates
    the action (`ROUTE_UNDERSTATES_ACTION`) or cannot be re-derived
    (`ROUTE_NOT_REDERIVABLE_FAIL_CLOSED`).

    R7 (F-W2R6-EXT-001): the TRUSTED ROUTE-ADMISSION BOUNDARY runs BEFORE the benign NONE return.
    Without it a caller could lower every route-driving field (operation / effect_risk_tier /
    permission_class / autonomy_tier) to a benign combination, reach `route.required == False`, and
    the verifier would never run. So, when a request is supplied and the route is not required:

      1. the CURRENT canonical request is resolved through the EXISTING owner-injected
         `request_resolver` (reusing `_resolve_current_request`); an absent resolver (including a
         missing `ctx`) or an unresolvable/stale/foreign request FAILS CLOSED with
         `DENY_REQUEST_UNRESOLVED`;
      2. the caller request is pinned to the trusted request on the policy-owned fields
         (`_REQUEST_POLICY_FIELDS`); any divergence FAILS CLOSED with
         `DENY_REQUEST_POLICY_MISMATCH`;
      3. RUIN / UNKNOWN_RUIN precedence is evaluated from the TRUSTED request; and
      4. the SUPPLIED route must equal the trusted-derived route on `required`, `route` and
         `authority_edge`, or the route understates the action (`ROUTE_UNDERSTATES_ACTION`).

    Only then is a trusted-derived `required=False` honoured as the benign NONE return. A supplied
    `ApprovalRequest` is therefore never honoured as benign without a trusted resolver. The R6
    verifier-level `request_resolver` pinning INSIDE `verify_approval_token` is kept as
    defense-in-depth for the gated path, which continues to require a typed, exact-bound
    `ApprovalToken`.

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

        # R7 (F-W2R6-EXT-001): TRUSTED ROUTE ADMISSION. Resolve the CURRENT canonical request
        # BEFORE honouring the benign NONE return, so a caller-declared policy downgrade can never
        # reach the early return without the owner-injected trusted resolver agreeing.
        if ctx is None:
            raise HumanGateBypassAttempt("DENY_REQUEST_UNRESOLVED")
        trusted = _resolve_current_request(ctx, getattr(request, "request_id", None))
        if trusted is None:
            raise HumanGateBypassAttempt("DENY_REQUEST_UNRESOLVED")
        # R7 parity with the R6 verifier path: the resolved request must be the SAME canonical
        # request_id; a resolver returning a foreign request is refused (defense-in-depth).
        if getattr(trusted, "request_id", None) != getattr(request, "request_id", None):
            raise HumanGateBypassAttempt("DENY_REQUEST_UNRESOLVED")
        mismatched = [
            name for name in _REQUEST_POLICY_FIELDS
            if getattr(request, name, None) != getattr(trusted, name, None)
        ]
        if mismatched:
            raise HumanGateBypassAttempt("DENY_REQUEST_POLICY_MISMATCH")

        # RUIN precedence is taken from the TRUSTED request before the benign return.
        ruin = _ruin_veto_code(trusted)
        if ruin is not None:
            raise HumanGateBypassAttempt(ruin)

        # The SUPPLIED route must equal the trusted-derived route on required+route+authority_edge.
        trusted_route = human_gate_required(trusted)
        if (trusted_route.required, trusted_route.route, trusted_route.authority_edge) != (
                route.required, route.route, route.authority_edge):
            raise HumanGateBypassAttempt("ROUTE_UNDERSTATES_ACTION")
        return

    if not isinstance(approval, ApprovalToken) or request is None or ctx is None:
        if request is not None and _requires_typed_token(request):
            raise HumanGateBypassAttempt("DENY_P3_TOKEN_REQUIRED")
        raise HumanGateBypassAttempt("NOT_A_CANONICAL_APPROVAL_TOKEN")

    # Gated path: the R6 verifier-level trusted-request boundary pins the caller request to the
    # resolved CURRENT request and takes the authn floor from the TRUSTED request (defense-in-depth).
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
    "classify_operation", "operation_classes",
    "RUIN_HARD_VETO_ROUTE", "RUIN_SAFE_STOP_ROUTE", "ApprovalDecision", "ApprovalRequest",
    "ApprovalToken", "HumanGateBypassAttempt", "HumanGateRoute", "NonceLedger", "RightsDecision",
    "RightsDenied", "RightsScope", "VerificationContext", "assert_credential_scope",
    "assert_human_gate_satisfied", "check_rights", "currentness_required", "human_gate_required",
    "human_gate_route", "verify_approval_token",
]
