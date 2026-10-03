"""Idempotency: one attempt key per intended effect, and a hard ceiling on retries.

WHY: a retry is how one intended side effect becomes two real ones. An attempt key derived from
the immutable intent identity means the same logical attempt can never fire twice, and a retry
plan is refused for any state where a second side effect would be wrong. A retry is allowed
ONLY from UNKNOWN_EFFECT; a PARTIAL_EFFECT has already applied part of the intent and is
answered with a fresh READBACK (plan_reobserve) plus a compensation pointer, never with
another side effect. max_retries is a ceiling, not a suggestion: exceeding it refuses rather
than looping.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from effect.state import TERMINAL_STATES, is_unknown

ATTEMPT_KEY_DOMAIN = "swof.effect.attempt.v1"

# Retry is allowed ONLY from UNKNOWN_EFFECT, where no effect has been confirmed applied. A
# PARTIAL_EFFECT has confirmed part of the intent, so a second side effect would compound it;
# its recovery route is a fresh readback (plan_reobserve) plus the compensation pointer. A
# MID-FLIGHT state (ATTEMPTED/OBSERVED/READBACK) may already have a side effect in the world, so
# it too is refused: the documented path is finalize() (which normalises it to UNKNOWN_EFFECT)
# and then a retry, or a re-observe.
RETRYABLE_STATES = ("UNKNOWN_EFFECT",)


class DuplicateAttemptDetected(Exception):
    """An attempt with this key was already recorded; refusing a duplicate side effect."""

    code = "ERR_DUPLICATE_ATTEMPT"


class RetryRefused(Exception):
    """A retry was requested for a state where a second side effect would be wrong."""

    code = "ERR_RETRY_REFUSED"


def attempt_key(effect_id, subject_id, intent_digest, attempt_no) -> str:
    """Deterministic sha256 hex for one (effect, subject, intent, attempt_no) attempt."""
    if not isinstance(attempt_no, int) or isinstance(attempt_no, bool) or attempt_no < 1:
        raise ValueError("attempt_no must be a positive int, got %r" % (attempt_no,))
    material = "%s%d:%s|%d:%s|%d:%s|%s:%d" % (
        ATTEMPT_KEY_DOMAIN, len(str(effect_id)), str(effect_id),
        len(str(subject_id)), str(subject_id),
        len(str(intent_digest)), str(intent_digest),
        "attempt_no", attempt_no)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _existing_keys(record) -> set:
    return {attempt.attempt_key for attempt in record.attempts}


def _is_retry_refused(record) -> bool:
    """True unless the record is in a state from which a retry may be planned.

    A retry is allowed ONLY from UNKNOWN_EFFECT. Every other state is refused: a terminal state
    outside RETRYABLE_STATES has already decided the effect, and a non-terminal (mid-flight)
    state may already have a side effect applied.
    """
    return record.state not in RETRYABLE_STATES


def classify_retry(record, *, attempt_no) -> str:
    """Classify a requested attempt: "NEW", "DUPLICATE" or "REFUSED"."""
    key = attempt_key(record.effect_id, record.subject_id, record.intent_digest, attempt_no)
    if key in _existing_keys(record):
        return "DUPLICATE"
    if _is_retry_refused(record):
        return "REFUSED"
    return "NEW"


@dataclass(frozen=True)
class RetryPlan:
    """A planned retry. `allowed` is the only thing to trust; nothing is executed here."""

    allowed: bool
    next_attempt_no: int
    reason_code: str
    idempotency_key: str


def _next_attempt_no(record) -> int:
    return len(record.attempts) + 1


def plan_retry(record, *, max_retries=3) -> RetryPlan:
    """Plan the next attempt, or refuse with a typed reason. Never executes anything.

    A retry is allowed ONLY from UNKNOWN_EFFECT. A terminal state outside RETRYABLE_STATES is
    refused as RETRY_REFUSED_<state>; a mid-flight state (ATTEMPTED/OBSERVED/READBACK) is
    refused as RETRY_REFUSED_MID_FLIGHT.
    """
    attempt_no = _next_attempt_no(record)
    key = attempt_key(record.effect_id, record.subject_id, record.intent_digest, attempt_no)
    if _is_retry_refused(record):
        if record.state in TERMINAL_STATES:
            return RetryPlan(False, attempt_no, "RETRY_REFUSED_%s" % record.state, key)
        return RetryPlan(False, attempt_no, "RETRY_REFUSED_MID_FLIGHT", key)
    if len(record.attempts) >= max_retries:
        return RetryPlan(False, attempt_no, "RETRY_LIMIT_EXCEEDED", key)
    if key in _existing_keys(record):
        return RetryPlan(False, attempt_no, "DUPLICATE_ATTEMPT", key)
    return RetryPlan(True, attempt_no, "RETRY_ALLOWED", key)


def assert_retryable(record, *, attempt_no, max_retries=3) -> RetryPlan:
    """Plan a retry for an explicit attempt_no or raise the exact typed refusal.

    A retry is allowed ONLY from UNKNOWN_EFFECT. A duplicate key raises DuplicateAttemptDetected;
    a terminal state outside RETRYABLE_STATES or a mid-flight state raises RetryRefused.
    """
    key = attempt_key(record.effect_id, record.subject_id, record.intent_digest, attempt_no)
    if key in _existing_keys(record):
        raise DuplicateAttemptDetected(
            "attempt %d for effect %r already exists (duplicate side effect refused)"
            % (attempt_no, record.effect_id))
    if _is_retry_refused(record):
        if record.state in TERMINAL_STATES:
            raise RetryRefused(
                "retry refused for terminal state %s (cannot justify a second side effect)"
                % record.state)
        raise RetryRefused(
            "retry refused for mid-flight state %s (a side effect may already be applied; "
            "finalize it to UNKNOWN_EFFECT, then retry, or re-observe)" % record.state)
    if attempt_no > max_retries:
        raise RetryRefused(
            "retry refused: attempt_no %d exceeds max_retries %d (hard ceiling)"
            % (attempt_no, max_retries))
    return RetryPlan(True, attempt_no, "RETRY_ALLOWED", key)


def plan_reobserve(record) -> dict:
    """Ask for a fresh READBACK (never a new side effect) when the outcome is uncertain."""
    if is_unknown(record.state):
        return {"reobserve": True, "reason_code": "REOBSERVE_UNCERTAIN_%s" % record.state}
    return {"reobserve": False, "reason_code": "REOBSERVE_NOT_APPLICABLE"}
