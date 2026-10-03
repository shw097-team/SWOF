"""Effect state machine: the closed alphabet of effect states and its legal transitions.

WHY: an effect is not "done" because someone said so. Before any reconciliation machinery can
be trusted, the set of states must be finite and closed, and the legal edges between them must
be explicit. This module is that alphabet and those edges - nothing here executes anything or
touches the world. `OBSERVED -> RECONCILED` is deliberately NOT an edge: a provider response is
an OBSERVATION, and the only route to truth is a fresh readback (OBSERVED -> READBACK ->
RECONCILED). Unknown state names are refused rather than coerced, so a typo cannot silently
create a new state. Fail closed.
"""
from __future__ import annotations

INTENT_STATES = ("INTENDED", "ATTEMPTED", "OBSERVED", "READBACK")
TERMINAL_STATES = ("RECONCILED", "UNKNOWN_EFFECT", "PARTIAL_EFFECT", "DENIED", "FAILED",
                   "COMPENSATED", "IRREVERSIBLE")
EFFECT_STATES = INTENT_STATES + TERMINAL_STATES

UNKNOWN_STATES = ("UNKNOWN_EFFECT", "PARTIAL_EFFECT")


class EffectTransitionRefused(Exception):
    """A transition, or a query over an unknown state, was refused (fail closed)."""

    code = "ERR_EFFECT_TRANSITION_REFUSED"


# The single source of truth for legal edges.
# Intent chain: INTENDED -> ATTEMPTED -> OBSERVED -> READBACK.
# DENIED is reachable only from INTENDED (a refusal happens before any attempt).
# READBACK is the only state that may reach RECONCILED.
_ALLOWED = {
    "INTENDED": ("ATTEMPTED", "DENIED"),
    "ATTEMPTED": ("OBSERVED", "FAILED"),
    "OBSERVED": ("READBACK", "FAILED"),
    "READBACK": ("RECONCILED", "UNKNOWN_EFFECT", "PARTIAL_EFFECT"),
    "RECONCILED": (),
    "UNKNOWN_EFFECT": (),
    "PARTIAL_EFFECT": ("COMPENSATED",),
    "DENIED": (),
    "FAILED": (),
    "COMPENSATED": (),
    "IRREVERSIBLE": (),
}

ALLOWED_TRANSITIONS = {state: frozenset(_ALLOWED[state]) for state in EFFECT_STATES}

# Stable rank for deterministic ordering and for reporting a linearised state.
_STATE_RANK = {state: index for index, state in enumerate(EFFECT_STATES)}


def _check_state(state) -> str:
    if not isinstance(state, str) or state not in ALLOWED_TRANSITIONS:
        raise EffectTransitionRefused(
            "unknown effect state %r; refusing to guess (fail closed)" % (state,))
    return state


def is_terminal(state) -> bool:
    """True for a terminal state. An unknown state is refused, never guessed."""
    return _check_state(state) in TERMINAL_STATES


def is_unknown(state) -> bool:
    """True for UNKNOWN_EFFECT and PARTIAL_EFFECT - uncertainty is first-class, not an error."""
    return _check_state(state) in UNKNOWN_STATES


def assert_transition(src, dst) -> tuple[str, str]:
    """Return (src, dst) when the edge is legal, else raise EffectTransitionRefused."""
    source = _check_state(src)
    target = _check_state(dst)
    if target not in ALLOWED_TRANSITIONS[source]:
        raise EffectTransitionRefused(
            "transition %s -> %s is not allowed (the only route to RECONCILED is "
            "OBSERVED -> READBACK -> RECONCILED)" % (source, target))
    return source, target


def state_rank(state) -> int:
    """Stable rank for deterministic ordering; unknown states are refused."""
    return _STATE_RANK[_check_state(state)]
