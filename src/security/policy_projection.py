"""PI06 minimum-policy conformance projection (W2 R8/R9; F-W2R7-EXT-001 / F-W2R8-EXT-001).

WHY: R6/R7 pin the caller request to the TRUSTED request, but nothing proved the TRUSTED
request itself meets the FROZEN PI06 minimum policy. A trusted `release` request declaring
P2/LOW/T2/AAC2/checker=false was accepted, `required_coapprovals` could not be represented, and
the T3/checker floor was not canonically enforced. This module is ONE read-only projection of the
frozen PI-PKG-06 DOC-03 minimum policy: it derives the lower bound for a canonical action class
and reports the concrete reasons a request falls below it.

R9 (F-W2R8-EXT-001, DOMAIN-BOUNDARY CORRECTION): R8 collapsed several DISTINCT canonical PI06
action classes into one generic `ACT-T3-HUMAN` row, ALIASED `ACT-EXTERNAL-WRITE-STATEFUL` and
`ACT-DATA-EXPORT` onto `ACT-EXTERNAL-WRITE-REV`, dropped the ACT-MERGE risk/domain coapproval, and
gave the stateful write no floor of its own. That erased the canonical action identity and the
per-domain floors. R9 preserves the exact canonical action class for every known consequential
action, splits the floors (`ACT-MERGE` gains its mapped HA3 risk/domain coapproval; the stateful
write gains its own HIGH floor and a CRITICAL owner-boundary), and represents the domain-owned
actions (`ACT-FINANCIAL`, `ACT-PHYSICAL`, `ACT-DATA-EXPORT`) as OWNER_BOUNDARY_DEFERRED instead of
inventing an HA or lowering them onto a generic row. A deferred action is TEMP-CLOSED, never benign.

It is a refusal input, never an authority grant, and never a second policy engine: the reserved
operation vocabulary and the canonical domains are REUSED (lazily) from `rights` / `humangate`,
so there is exactly one classifier and one enum source. It defines NO HA ordering - a PI06 clause
is a SET the request's authority composition must COVER. A clause that names a DOMAIN (e.g.
`HA3_Physical`) is never synthesized from a caller field: when the owner context is absent the
projection defers (TEMP-CLOSED), it never guesses.
"""
from __future__ import annotations

from dataclasses import dataclass

# Ordered canonical domains (PI06 DOC-03). These are the ONLY orderings this module knows.
PERMISSION_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
AUTHN_ORDER = {"AAC1": 1, "AAC2": 2, "AAC3": 3}
# Non-ruin risk order. RUIN / UNKNOWN_RUIN are deliberately NOT rank values here: they keep their
# existing hard precedence (HARD_VETO / SAFE_STOP) and are handled before any floor comparison.
RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RUIN_TIERS = ("RUIN", "UNKNOWN_RUIN")

# The canonical action classes this projection resolves to. The clause vocabulary uses ONLY
# HA1/HA3/HA5 (the PI06 frozen set); no other HA number is invented. R9: every canonical PI06
# consequential class is a DISTINCT identity - there is no generic ACT-T3-HUMAN collapse.
ACT_DEPLOY_RELEASE = "ACT-DEPLOY-RELEASE"
ACT_MERGE = "ACT-MERGE"
ACT_SECRET_RESOLVE = "ACT-SECRET-RESOLVE"
ACT_EXTERNAL_WRITE_REV = "ACT-EXTERNAL-WRITE-REV"
ACT_EXTERNAL_WRITE_STATEFUL = "ACT-EXTERNAL-WRITE-STATEFUL"
ACT_IDENTITY_RIGHTS = "ACT-IDENTITY-RIGHTS"
ACT_FINANCIAL = "ACT-FINANCIAL"
ACT_PHYSICAL = "ACT-PHYSICAL"
ACT_DELETE_IRREV = "ACT-DELETE-IRREV"
ACT_DATA_EXPORT = "ACT-DATA-EXPORT"

# Non-canonical/unconsequential names that carry no floor (KNOWN benign operations).
_BENIGN_OPERATIONS = frozenset({"read", "ACT-READ-LOCAL", "ACT-DESIGN-WRITE", "ACT-EXTERNAL-READ"})

# Operation name -> canonical action class (R9: identity-preserving, no aliases). Both the
# canonical action-class names (09.1 matrix) and the high-risk operation names the gate already
# names are accepted; the mapping is a total function over the KNOWN vocabulary, and anything else
# is UNRESOLVED (fail closed).
_ACTION_BY_OPERATION = {
    "release": ACT_DEPLOY_RELEASE,
    "production_promotion": ACT_DEPLOY_RELEASE,
    "ACT-DEPLOY-RELEASE": ACT_DEPLOY_RELEASE,
    "remote_merge": ACT_MERGE,
    "ACT-MERGE": ACT_MERGE,
    "credential_access": ACT_SECRET_RESOLVE,
    "ACT-SECRET-RESOLVE": ACT_SECRET_RESOLVE,
    "ACT-EXTERNAL-WRITE-REV": ACT_EXTERNAL_WRITE_REV,
    "ACT-EXTERNAL-WRITE-STATEFUL": ACT_EXTERNAL_WRITE_STATEFUL,
    "ACT-IDENTITY-RIGHTS": ACT_IDENTITY_RIGHTS,
    "ACT-DELETE-IRREV": ACT_DELETE_IRREV,
}

# R9: canonical actions whose PI06 floor is OWNER-BOUNDARY. The projection cannot synthesize the
# domain coapproval (HA3 financial / HA3_Physical / a data-class-derived export clause) from any
# caller field, so an unresolved one is DEFERRED (TEMP_CLOSED_POLICY_RESOLUTION), never benign and
# never collapsed onto another class. The canonical action IDENTITY is still preserved.
_OWNER_BOUNDARY_DEFERRED = frozenset({
    ACT_FINANCIAL,
    ACT_PHYSICAL,
    ACT_DATA_EXPORT,
    ACT_IDENTITY_RIGHTS,
    ACT_DELETE_IRREV,
})

# Reason prefixes. A caller maps these to the canonical deny codes.
TEMP_CLOSED_POLICY_RESOLUTION = "TEMP_CLOSED_POLICY_RESOLUTION"
OWNER_BOUNDARY_DEFERRED = "OWNER_BOUNDARY_DEFERRED"
COAPPROVAL_MALFORMED = "COAPPROVAL_MALFORMED"

# Frozen PI06 minimum policy table (DOC-03). A clause is a frozenset the composition must COVER.
# R9: distinct canonical rows, no ACT-T3-HUMAN collapse and no REV aliasing. ACT-MERGE carries its
# mapped HA3 risk/domain coapproval; the stateful write has its own HIGH floor.
_MINIMUM_POLICY = {
    ACT_DEPLOY_RELEASE: dict(
        permission="P5", risk="CRITICAL", autonomy="T3", authn="AAC3", checker=True,
        clauses=(frozenset({"HA1", "HA5"}),)),
    ACT_MERGE: dict(
        permission="P5", risk="CRITICAL", autonomy="T3", authn="AAC3", checker=True,
        clauses=(frozenset({"HA1", "HA3"}),)),
    ACT_SECRET_RESOLVE: dict(
        permission="P4", risk="CRITICAL", autonomy=None, authn="AAC3", checker=False,
        clauses=(frozenset({"HA1", "HA3"}),)),
    ACT_EXTERNAL_WRITE_REV: dict(
        permission="P3", risk="MEDIUM", autonomy=None, authn="AAC1", checker=False,
        clauses=(frozenset({"HA1"}), frozenset({"HA2"}))),
    ACT_EXTERNAL_WRITE_STATEFUL: dict(
        permission="P3", risk="HIGH", autonomy=None, authn="AAC2", checker=False,
        clauses=(frozenset({"HA1"}),)),
    ACT_IDENTITY_RIGHTS: dict(
        permission="P3", risk="CRITICAL", autonomy=None, authn="AAC3", checker=True,
        clauses=(frozenset({"HA1", "HA3", "HA5"}),)),
    ACT_DELETE_IRREV: dict(
        permission="P3", risk="CRITICAL", autonomy=None, authn="AAC2", checker=False,
        clauses=(frozenset({"HA1"}),)),
}


@dataclass(frozen=True)
class MinimumPolicy:
    """The frozen PI06 lower bound for one canonical action class.

    `resolved` is False for an action the canonical vocabulary cannot classify OR whose floor the
    projection may not own: the caller MUST fail closed (TEMP_CLOSED_POLICY_RESOLUTION), never treat
    it as benign. `consequential` is False for a KNOWN benign operation (no gate, no floor).
    `deferred_reason` is set (OWNER_BOUNDARY_DEFERRED) when the identity is known but the DOMAIN
    floor belongs to another owner, so the caller fails closed instead of guessing.
    """

    action_class: str
    resolved: bool
    consequential: bool
    permission_floor: str | None = None
    risk_floor: str | None = None
    autonomy_tier: str | None = None
    clauses: tuple[frozenset[str], ...] = ()
    authn_floor: str | None = None
    checker_required: bool = False
    deferred_reason: str | None = None


def classify_action(operation):
    """The canonical action class for an operation name, or None when unresolved.

    R9: the canonical identity is returned even for an owner-boundary DEFERRED action (the class
    is known, only its domain floor is not ours to own). A KNOWN benign operation maps to None
    *and* is reported as benign by `minimum_policy`; an unrecognised/absent/malformed operation is
    UNRESOLVED (None, fail closed).
    """
    if not isinstance(operation, str):
        return None
    if operation in _OWNER_BOUNDARY_DEFERRED:
        return operation
    return _ACTION_BY_OPERATION.get(operation)


def minimum_policy(action_or_operation, effect_risk_tier=None, permission_class=None):
    """Deterministic PI06 minimum policy for an action/operation. Never guesses.

    R9: the lower bound is a property of the canonical ACTION CLASS. The caller-declared
    `effect_risk_tier` / `permission_class` are NOT used to lower a floor; they are read ONLY to
    recognise the stateful-write CRITICAL owner-boundary, which DEFERS (fail closed) instead.

    An OWNER-BOUNDARY-DEFERRED action returns `resolved=False` with `deferred_reason` set; the
    caller MUST fail closed (TEMP_CLOSED_POLICY_RESOLUTION). This is never a benign default.
    """
    from . import rights  # lazy: avoids an import cycle (rights -> humangate -> policy_projection)

    state, value = rights.classify_operation(action_or_operation)
    if state != rights._CLASS_VALID:
        return MinimumPolicy(action_class="", resolved=False, consequential=False)
    if value in _BENIGN_OPERATIONS:
        return MinimumPolicy(action_class="", resolved=True, consequential=False)
    if value in _OWNER_BOUNDARY_DEFERRED:
        return MinimumPolicy(action_class=value, resolved=False, consequential=False,
                             deferred_reason=OWNER_BOUNDARY_DEFERRED)
    if value == ACT_EXTERNAL_WRITE_STATEFUL and effect_risk_tier in (("CRITICAL",) + RUIN_TIERS):
        # R9: a STATEFUL write at CRITICAL needs the rollback/reconciliation domain coapproval
        # (HA3) that this projection does not own; DEFER rather than invent a clause.
        return MinimumPolicy(action_class=value, resolved=False, consequential=False,
                             deferred_reason=OWNER_BOUNDARY_DEFERRED)
    action = _ACTION_BY_OPERATION.get(value)
    if action is None:
        return MinimumPolicy(action_class="", resolved=False, consequential=False)
    row = _MINIMUM_POLICY[action]
    return MinimumPolicy(
        action_class=action, resolved=True, consequential=True,
        permission_floor=row["permission"], risk_floor=row["risk"], autonomy_tier=row["autonomy"],
        clauses=row["clauses"], authn_floor=row["authn"], checker_required=row["checker"])


def coapproval_refs_valid(refs):
    """True when `refs` is a canonical authority-ref set: tuple, unique, sorted, non-empty atoms."""
    if not isinstance(refs, tuple):
        return False
    if not all(isinstance(ref, str) and ref.strip() for ref in refs):
        return False
    if len(set(refs)) != len(refs):
        return False
    return list(refs) == sorted(refs)


def policy_floor_errors(request):
    """Concrete PI06 floor violations for a request; empty tuple means the floor is met.

    Raises nothing: unknown/malformed inputs and owner-boundary deferrals become reasons so the
    caller fails closed.
    """
    operation = getattr(request, "operation", None)
    tier = getattr(request, "effect_risk_tier", None)
    permission = getattr(request, "permission_class", None)
    policy = minimum_policy(operation, effect_risk_tier=tier, permission_class=permission)
    if policy.deferred_reason == OWNER_BOUNDARY_DEFERRED:
        return ("%s:%s" % (TEMP_CLOSED_POLICY_RESOLUTION, OWNER_BOUNDARY_DEFERRED),)
    if not policy.resolved:
        return ("%s:unresolved_action" % TEMP_CLOSED_POLICY_RESOLUTION,)
    if not policy.consequential:
        return ()

    errors = []
    if permission not in PERMISSION_ORDER or PERMISSION_ORDER[permission] < \
            PERMISSION_ORDER[policy.permission_floor]:
        errors.append("PERMISSION_FLOOR:%r<%s" % (permission, policy.permission_floor))

    if tier in RUIN_TIERS:
        pass  # ruin precedence owns this; not an ordinary rank value
    elif tier not in RISK_ORDER or RISK_ORDER[tier] < RISK_ORDER[policy.risk_floor]:
        errors.append("RISK_FLOOR:%r<%s" % (tier, policy.risk_floor))

    authn = getattr(request, "required_authn_assurance", None)
    if authn not in AUTHN_ORDER or AUTHN_ORDER[authn] < AUTHN_ORDER[policy.authn_floor]:
        errors.append("AUTHN_FLOOR:%r<%s" % (authn, policy.authn_floor))

    if policy.autonomy_tier == "T3":
        if getattr(request, "autonomy_tier", None) != "T3" \
                or getattr(request, "independent_checker_required", None) is not True:
            errors.append("T3_CHECKER:explicit_human_and_checker_required")

    refs = getattr(request, "required_coapprovals", ())
    if not coapproval_refs_valid(refs):
        errors.append("%s:not_canonical_authority_ref_set" % COAPPROVAL_MALFORMED)
        composition = frozenset()
    else:
        composition = frozenset(ref for ref in (getattr(request, "required_authority", ""),)
                                if isinstance(ref, str) and ref.strip())
        composition |= frozenset(refs)
    if not any(clause <= composition for clause in policy.clauses):
        errors.append("AUTHORITY_FLOOR:no_pi06_clause_covered")
    return tuple(errors)


def policy_deny_code(errors, default="DENY_POLICY_FLOOR"):
    """Map `policy_floor_errors` reasons to the canonical deny code, or None when the floor is met."""
    if not errors:
        return None
    if any(reason.startswith(TEMP_CLOSED_POLICY_RESOLUTION) for reason in errors):
        return "TEMP_CLOSED_POLICY_RESOLUTION"
    if all(reason.startswith("T3_CHECKER") for reason in errors):
        return "DENY_T3_CHECKER"
    if any(reason.startswith(COAPPROVAL_MALFORMED) for reason in errors):
        return "DENY_COAPPROVAL"
    return default


__all__ = [
    "MinimumPolicy", "ACT_DEPLOY_RELEASE", "ACT_MERGE", "ACT_SECRET_RESOLVE",
    "ACT_EXTERNAL_WRITE_REV", "ACT_EXTERNAL_WRITE_STATEFUL", "ACT_IDENTITY_RIGHTS", "ACT_FINANCIAL",
    "ACT_PHYSICAL", "ACT_DELETE_IRREV", "ACT_DATA_EXPORT", "PERMISSION_ORDER", "AUTHN_ORDER",
    "RISK_ORDER", "classify_action", "minimum_policy", "policy_floor_errors", "policy_deny_code",
    "coapproval_refs_valid", "TEMP_CLOSED_POLICY_RESOLUTION", "OWNER_BOUNDARY_DEFERRED",
    "COAPPROVAL_MALFORMED",
]
