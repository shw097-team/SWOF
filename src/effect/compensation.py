"""Compensation: classify reversibility and PLAN a compensation path. Never execute one.

WHY: an effect that cannot be undone must say so, loudly, before anyone tries to "clean up".
An effect with a declared irreversible attempt classifies as IRREVERSIBLE and yields a pointer
that is explicitly not compensable. A PARTIAL_EFFECT with a registered path yields a
COMPENSATE/ROLLBACK pointer carrying an exact ref; with no registered path it is refused with
NoCompensationPath rather than silently passed. Planning is all that happens here - no rollback
is ever executed by this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from effect.state import is_unknown

COMPENSABLE_KINDS = ("COMPENSATE", "ROLLBACK")

IRREVERSIBLE_REASON = "IRREVERSIBLE_EFFECT"
NO_PATH_REASON = "NO_COMPENSATION_PATH"


class IrreversibleEffect(Exception):
    """The effect (or one of its attempts) cannot be undone; compensation is impossible."""

    code = "ERR_IRREVERSIBLE_EFFECT"


class NoCompensationPath(Exception):
    """No compensation path is registered for this effect; explicit refusal, not a silent pass."""

    code = "ERR_NO_COMPENSATION_PATH"


@dataclass(frozen=True)
class CompensationPointer:
    """A pointer at a planned (never executed) compensation. `ref` is the exact target."""

    target_effect_id: str
    ref: str
    kind: str
    compensable: bool
    reason_code: str


def _has_irreversible(record, irreversible_attempts) -> bool:
    declared = set(irreversible_attempts or ())
    if not declared:
        return False
    keys = {attempt.attempt_key for attempt in record.attempts}
    if keys & declared:
        return True
    # A caller may declare an attempt number/identity that has not been recorded yet.
    if record.effect_id in declared:
        return True
    return False


def classify(record, *, irreversible_attempts=()) -> str:
    """Classify the effect as IRREVERSIBLE when any declared attempt is irreversible."""
    if _has_irreversible(record, irreversible_attempts):
        return "IRREVERSIBLE"
    return record.state


def _registry_ref(registry, record):
    if registry is None:
        return None
    if isinstance(registry, dict):
        return registry.get(record.effect_id) or registry.get(record.subject_id)
    return None


def plan_compensation(record, *, registry=None, irreversible_attempts=()) -> CompensationPointer:
    """Plan compensation, or raise. There is no execution path here."""
    if classify(record, irreversible_attempts=irreversible_attempts) == "IRREVERSIBLE":
        return CompensationPointer(
            target_effect_id=record.effect_id, ref="", kind="NONE", compensable=False,
            reason_code=IRREVERSIBLE_REASON)
    if record.state != "PARTIAL_EFFECT" and not is_unknown(record.state):
        return CompensationPointer(
            target_effect_id=record.effect_id, ref="", kind="NONE", compensable=False,
            reason_code="NOT_COMPENSABLE_STATE")
    if record.state != "PARTIAL_EFFECT":
        return CompensationPointer(
            target_effect_id=record.effect_id, ref="", kind="NONE", compensable=False,
            reason_code="NOT_PARTIAL_EFFECT")
    ref = _registry_ref(registry, record)
    if ref is None:
        raise NoCompensationPath(
            "no compensation path registered for partial effect %r" % record.effect_id)
    kind = ref.get("kind") if isinstance(ref, dict) else None
    target = ref.get("ref") if isinstance(ref, dict) else None
    if kind not in COMPENSABLE_KINDS or not target:
        raise NoCompensationPath(
            "registered compensation ref for %r is not a COMPENSATE/ROLLBACK pointer with an "
            "exact ref" % record.effect_id)
    return CompensationPointer(
        target_effect_id=record.effect_id, ref=target, kind=kind, compensable=True,
        reason_code="COMPENSATION_PLANNED")


def assert_compensable(pointer) -> CompensationPointer:
    """Return the pointer when it is compensable, else raise IrreversibleEffect."""
    if not isinstance(pointer, CompensationPointer):
        raise IrreversibleEffect("not a CompensationPointer; refusing (fail closed)")
    if not pointer.compensable:
        if pointer.reason_code == IRREVERSIBLE_REASON:
            raise IrreversibleEffect(
                "effect %r is irreversible; no compensation is possible"
                % pointer.target_effect_id)
        raise NoCompensationPath(
            "effect %r has no compensable path (%s)"
            % (pointer.target_effect_id, pointer.reason_code))
    return pointer
