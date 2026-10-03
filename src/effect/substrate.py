"""Effect substrate: a state machine over records, NOT an executor.

WHY: there is no live effect in this module. Every function returns a new immutable
`EffectRecord`; nothing performs a network call, a subprocess, a filesystem write or a
broker/business action. The central law is that a provider response is an OBSERVATION, never
world-state truth: `observe(provider_success=True)` moves ATTEMPTED -> OBSERVED and nothing
more. Only a fresh readback whose payload matches the intended effect can reach RECONCILED.
When that cannot be established the record fails closed into UNKNOWN_EFFECT (or PARTIAL_EFFECT
when only part of the intent is proven) - first-class terminal states, not errors to retry away.
Each function accepts an injected `at`, so no wall-clock enters a decision.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from effect.idempotency import DuplicateAttemptDetected
from effect.state import assert_transition, is_terminal

INTENT_DIGEST_DOMAIN = "swof.effect.intent.v1"


class EffectDenied(Exception):
    """An attempt was refused by permission; the effect is DENIED, not attempted."""

    code = "ERR_EFFECT_DENIED"


class EffectStateError(Exception):
    """The record cannot accept this operation (wrong state, or wrong subject evidence)."""

    code = "ERR_EFFECT_STATE"
    reason_code = ""

    def __init__(self, message="", *, reason_code=""):
        super().__init__(message)
        self.reason_code = reason_code or type(self).reason_code


class SuccessInferenceRefused(Exception):
    """Someone tried to infer success from anything other than a RECONCILED record."""

    code = "ERR_SUCCESS_INFERENCE_REFUSED"


@dataclass(frozen=True)
class Attempt:
    actor: str
    attempt_key: str
    at: str


@dataclass(frozen=True)
class Observation:
    payload: object
    provider_success: bool | None
    at: str


@dataclass(frozen=True)
class Readback:
    payload: object
    matches_expected: bool | None
    at: str
    stale: bool = False


@dataclass(frozen=True)
class EffectRecord:
    effect_id: str
    subject_id: str
    intent: object
    intent_digest: str
    state: str
    attempts: tuple[Attempt, ...] = ()
    observations: tuple[Observation, ...] = ()
    readbacks: tuple[Readback, ...] = ()
    provider_success: bool | None = None
    reason_code: str = ""
    correlation_id: str = ""
    environment: str = "local"


def _canonical(value) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False)
    except (TypeError, ValueError):
        return "repr:" + repr(value)


def _intent_digest(effect_id, subject_id, intent) -> str:
    material = "%s|identity:%s|intent:%s" % (
        INTENT_DIGEST_DOMAIN, _canonical([effect_id, subject_id]), _canonical(intent))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def intend(effect_id, subject_id, intent, *, environment="local") -> EffectRecord:
    """Create the initial INTENDED record and freeze its intent digest (immutable content)."""
    for name, value in (("effect_id", effect_id), ("subject_id", subject_id),
                        ("environment", environment)):
        if not isinstance(value, str) or not value:
            raise EffectStateError("%s must be a non-empty string, got %r" % (name, value))
    digest = _intent_digest(effect_id, subject_id, intent)
    return EffectRecord(effect_id=effect_id, subject_id=subject_id, intent=intent,
                        intent_digest=digest, state="INTENDED", environment=environment)


# A fresh attempt supersedes the previous observation cycle. Retry is recordable from these
# states when the attempt_key is NEW; every terminal state outside this set (RECONCILED,
# DENIED, FAILED, COMPENSATED, IRREVERSIBLE) still refuses.
RETRY_FROM_STATES = ("ATTEMPTED", "OBSERVED", "READBACK", "UNKNOWN_EFFECT", "PARTIAL_EFFECT")


def record_attempt(record, *, actor, permission_allowed, attempt_key, at) -> EffectRecord:
    """Record an attempt, or DENY the effect. A denied attempt is never recorded.

    A NEW attempt_key on a retryable state records a fresh attempt: the record returns to
    ATTEMPTED and the superseded observation cycle (observations/readbacks) is dropped, so a
    retry can only be reconciled by a readback of THAT attempt. A repeated attempt_key raises
    DuplicateAttemptDetected, and any other terminal state refuses with a typed error.
    """
    if not permission_allowed:
        assert_transition(record.state, "DENIED")
        return replace(record, state="DENIED", reason_code="PERMISSION_DENIED")
    existing = {attempt.attempt_key for attempt in record.attempts}
    if attempt_key in existing:
        raise DuplicateAttemptDetected(
            "attempt_key %r already recorded for effect %r (duplicate side effect refused)"
            % (attempt_key, record.effect_id))
    attempt = Attempt(actor=actor, attempt_key=attempt_key, at=at)
    if record.state in RETRY_FROM_STATES:
        return replace(record, state="ATTEMPTED", attempts=record.attempts + (attempt,),
                       observations=(), readbacks=(), provider_success=None, reason_code="")
    assert_transition(record.state, "ATTEMPTED")
    return replace(record, state="ATTEMPTED", attempts=record.attempts + (attempt,))


def observe(record, *, payload, provider_success, at) -> EffectRecord:
    """Record a provider OBSERVATION. This is evidence of a response, not of the world."""
    assert_transition(record.state, "OBSERVED")
    observation = Observation(payload=payload, provider_success=provider_success, at=at)
    return replace(record, state="OBSERVED", observations=record.observations + (observation,),
                   provider_success=provider_success, reason_code="")


def _expected_parts(intent):
    """Optional declared sub-effect parts. Only a declared collection enables PARTIAL_EFFECT."""
    if isinstance(intent, dict):
        for key in ("parts", "sub_effects", "expected"):
            value = intent.get(key)
            if isinstance(value, (list, tuple)) and len(value) > 0:
                return list(value)
    return None


def _declared_subject(payload, expected):
    """A subject named by the readback itself, if any. Evidence about another subject is refused."""
    for candidate in (payload, expected):
        if isinstance(candidate, dict) and "subject_id" in candidate:
            return candidate.get("subject_id")
    return None


def _matches(payload, expected):
    """True/False when the comparison is determinate; None when it is ambiguous."""
    if expected is None or payload is None:
        return None
    if isinstance(expected, (list, tuple)):
        return any(payload == part for part in expected)
    return payload == expected


def readback(record, *, payload, expected, at, stale=False) -> EffectRecord:
    """Record a readback of the world. Evidence about another subject is refused outright."""
    declared = _declared_subject(payload, expected)
    if declared is not None and declared != record.subject_id:
        raise EffectStateError(
            "readback subject %r does not match record subject %r (WRONG_SUBJECT_READBACK)"
            % (declared, record.subject_id), reason_code="WRONG_SUBJECT_READBACK")
    assert_transition(record.state, "READBACK")
    entry = Readback(payload=payload, matches_expected=_matches(payload, expected), at=at,
                     stale=bool(stale))
    return replace(record, state="READBACK", readbacks=record.readbacks + (entry,),
                   reason_code="")


def reconcile(record, *, at) -> EffectRecord:
    """Decide the terminal state from readbacks alone. Provider claims are never consulted."""
    if is_terminal(record.state):
        raise EffectStateError(
            "cannot reconcile effect %r from terminal state %s"
            % (record.effect_id, record.state), reason_code="TERMINAL_STATE")
    readbacks = record.readbacks
    if not readbacks:
        return replace(record, state="UNKNOWN_EFFECT", reason_code="NO_READBACK_FAIL_CLOSED")
    fresh = [rb for rb in readbacks if not rb.stale]
    if not fresh:
        return replace(record, state="UNKNOWN_EFFECT", reason_code="STALE_READBACK_FAIL_CLOSED")
    fresh_match = [rb for rb in fresh if rb.matches_expected is True]
    fresh_mismatch = [rb for rb in fresh if rb.matches_expected is False]
    if fresh_match:
        expected_parts = _expected_parts(record.intent)
        if expected_parts is not None and len(expected_parts) > 1:
            matched = [part for part in expected_parts
                       if any(rb.payload == part for rb in fresh_match)]
            if len(matched) == len(expected_parts) and not fresh_mismatch:
                return replace(record, state="RECONCILED", reason_code="")
            if matched:
                return replace(record, state="PARTIAL_EFFECT",
                               reason_code="PARTIAL_EFFECT_DETECTED")
            return replace(record, state="UNKNOWN_EFFECT",
                           reason_code="RECONCILIATION_MISMATCH")
        if fresh_mismatch:
            return replace(record, state="UNKNOWN_EFFECT",
                           reason_code="RECONCILIATION_MISMATCH")
        return replace(record, state="RECONCILED", reason_code="")
    if fresh_mismatch:
        return replace(record, state="UNKNOWN_EFFECT", reason_code="RECONCILIATION_MISMATCH")
    return replace(record, state="UNKNOWN_EFFECT", reason_code="AMBIGUOUS_READBACK_FAIL_CLOSED")


def finalize(record) -> EffectRecord:
    """Fail-closed sweep: no non-terminal record survives, and never an unjustified success."""
    try:
        if is_terminal(record.state):
            return record
        if record.state == "OBSERVED" and record.provider_success is True and not record.readbacks:
            return replace(record, state="UNKNOWN_EFFECT",
                           reason_code="NO_READBACK_AFTER_PROVIDER_SUCCESS")
        if record.state == "READBACK":
            at = record.readbacks[-1].at if record.readbacks else ""
            try:
                swept = reconcile(record, at=at)
            except EffectStateError:
                swept = record
            if is_terminal(swept.state):
                return swept
        return replace(record, state="UNKNOWN_EFFECT",
                       reason_code="UNRESOLVED_EFFECT_FAIL_CLOSED")
    except Exception:
        return replace(record, state="UNKNOWN_EFFECT",
                       reason_code="UNRESOLVED_EFFECT_FAIL_CLOSED")


def assert_no_success_inference(record) -> None:
    """Only a RECONCILED record may be read as success; everything else is refused."""
    if record.state != "RECONCILED":
        raise SuccessInferenceRefused(
            "effect %r is %s (provider_success=%r); success may not be inferred"
            % (record.effect_id, record.state, record.provider_success))
    return None


def is_success(record) -> bool:
    """True ONLY for a RECONCILED record. A green provider response is not success."""
    return record.state == "RECONCILED"
