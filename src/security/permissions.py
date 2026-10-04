"""Least-privilege permission envelopes: deny by default, no self-service widening.

WHY: an agent that reads "not denied" as "allowed" grants itself authority it was never given,
and an envelope that can be widened in place turns one granted capability into an unbounded one.
This module makes an unknown action a DENY and makes widening of a non-admitted action a typed
refusal, so a confused or hostile caller cannot manufacture authority it does not hold.
This guard grants nothing: it only refuses, and it is not a source of authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ALLOW = "ALLOW"
DENY = "DENY"


class PermissionDenied(Exception):
    """Action denied explicitly, or denied because it was never admitted."""

    code = "ERR_PERMISSION_DENIED"


class UnknownPermissionTarget(Exception):
    """Malformed envelope or action: fail closed instead of coercing a guess."""

    code = "ERR_UNKNOWN_PERMISSION_TARGET"


class HumanGateRequired(Exception):
    """The action is real but is usable only behind a human gate."""

    code = "ERR_HUMAN_GATE_REQUIRED"


class PermissionExpansionRefused(Exception):
    """A caller tried to widen an envelope beyond its effective actions."""

    code = "ERR_PERMISSION_EXPANSION_REFUSED"


@dataclass(frozen=True)
class PermissionEnvelope:
    """A subject's admitted actions. `default` is never a source of ALLOW."""

    subject: str
    allowed_actions: frozenset[str]
    denied_actions: frozenset[str] = field(default_factory=frozenset)
    human_gate_actions: frozenset[str] = field(default_factory=frozenset)
    default: str = DENY


@dataclass(frozen=True)
class Decision:
    """Outcome of an authorization probe. `allowed` is the only thing to trust."""

    allowed: bool
    reason_code: str
    requires_human_gate: bool
    matched_rule: str


def _validate_envelope(envelope) -> None:
    if not isinstance(envelope, PermissionEnvelope):
        raise UnknownPermissionTarget(
            "envelope is not a PermissionEnvelope; refusing to guess (fail closed)")
    if not isinstance(envelope.subject, str) or not envelope.subject:
        raise UnknownPermissionTarget("envelope subject must be a non-empty string")
    for label, value in (
        ("allowed_actions", envelope.allowed_actions),
        ("denied_actions", envelope.denied_actions),
        ("human_gate_actions", envelope.human_gate_actions),
    ):
        if not isinstance(value, frozenset):
            raise UnknownPermissionTarget(
                f"{label} must be a frozenset; refusing to coerce (fail closed)")
        for member in value:
            if not isinstance(member, str) or not member:
                raise UnknownPermissionTarget(
                    f"{label} entries must be non-empty strings, got {member!r}")


def _validate_action(action) -> None:
    if not isinstance(action, str) or not action:
        raise UnknownPermissionTarget(
            f"action must be a non-empty string, got {action!r} (fail closed)")


def _context_subject(context):
    if isinstance(context, dict):
        return context.get("subject")
    return None


def effective_actions(envelope) -> frozenset[str]:
    """Actions usable directly: allowed, minus explicit denials, minus human-gated ones."""
    _validate_envelope(envelope)
    return frozenset(envelope.allowed_actions
                     - envelope.denied_actions
                     - envelope.human_gate_actions)


def authorize(envelope, action, *, context=None) -> Decision:
    """Decide an action. Unknown, mismatched or malformed input DENIES."""
    _validate_envelope(envelope)
    _validate_action(action)
    bound = _context_subject(context)
    if bound is not None and bound != envelope.subject:
        return Decision(False, "SUBJECT_MISMATCH", False, "context.subject")
    if action in envelope.denied_actions:
        return Decision(False, "DENIED_EXPLICIT", False, "denied_actions")
    if action in envelope.human_gate_actions:
        return Decision(False, "HUMAN_GATE_REQUIRED", True, "human_gate_actions")
    if action in envelope.allowed_actions:
        return Decision(True, "ALLOWED_BY_ENVELOPE", False, "allowed_actions")
    return Decision(False, "UNKNOWN_ACTION_FAIL_CLOSED", False, "default")


def assert_authorized(envelope, action, *, context=None) -> Decision:
    """Same decision as `authorize`, but raises a typed error when not usable."""
    decision = authorize(envelope, action, context=context)
    if decision.requires_human_gate:
        raise HumanGateRequired(
            f"action {action!r} for subject {envelope.subject!r} requires a human gate "
            f"({decision.reason_code})")
    if not decision.allowed:
        raise PermissionDenied(
            f"action {action!r} denied for subject {envelope.subject!r} "
            f"({decision.reason_code})")
    return decision


def widen(envelope, action) -> PermissionEnvelope:
    """Return the envelope unchanged, or refuse: there is no self-service escalation."""
    _validate_envelope(envelope)
    _validate_action(action)
    if action not in effective_actions(envelope):
        raise PermissionExpansionRefused(
            f"refusing to widen {envelope.subject!r} with non-admitted action {action!r}")
    return envelope
