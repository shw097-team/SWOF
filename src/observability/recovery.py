"""Recovery / rollback hooks: an unmapped failure is an error, never a default action.

WHY: an implicit "best effort" recovery is the defect. If the registry has no action for a
failure kind, the honest answer is that no recovery path is registered - inventing one would
hide the failure behind a plausible-looking plan. `recovery_plan` therefore RAISES
`NoRecoveryPath` rather than returning a default, and every plan it does return carries the
rollback pointer, so recovery and rollback are never separable.

`deterministic_readback` is a pure function of the events: same events in, byte-identical
output out, so a replay cannot depend on when it is run or on process state.
"""
from __future__ import annotations

from observability.correlation import CorrelationContext
from observability.hooks import Event

SIG_KEYS = ("seq", "kind", "trace_id", "workorder_id", "checkpoint_id", "subject_id",
            "subject_sha", "invariant", "recovery_action")

RECOVERY_PLAN_SCHEMA = "SWOF-RECOVERY-PLAN/1"
ROLLBACK_POINTER_SCHEMA = "SWOF-ROLLBACK-POINTER/1"


class NoRecoveryPath(Exception):
    """No recovery action is registered for this failure kind (fail closed, no default)."""

    code = "ERR_NO_RECOVERY_PATH"

    def __init__(self, message, failure_kind=None):
        super().__init__(message)
        self.failure_kind = failure_kind


def rollback_pointer(*, workorder_id, baseline_sha):
    """A pointer back to the WorkOrder baseline the rollback would restore."""
    if not isinstance(workorder_id, str) or not workorder_id.strip():
        raise ValueError("workorder_id must be a non-empty string")
    if not isinstance(baseline_sha, str) or not baseline_sha.strip():
        raise ValueError("baseline_sha must be a non-empty string")
    return {
        "schema": ROLLBACK_POINTER_SCHEMA,
        "workorder_id": workorder_id,
        "baseline_sha": baseline_sha,
    }


def _as_dict(event):
    if isinstance(event, Event):
        return {"seq": event.seq, "kind": event.kind, "correlation": event.correlation,
                "payload": event.payload}
    if isinstance(event, dict):
        return event
    raise ValueError("failure_event must be an Event or a mapping, got %s"
                     % type(event).__name__)


def _field(event, name):
    source = _as_dict(event)
    if name in source:
        return source[name]
    correlation = source.get("correlation")
    if isinstance(correlation, CorrelationContext):
        return getattr(correlation, name, None)
    if isinstance(correlation, dict):
        return correlation.get(name)
    return None


def _payload(event):
    return _as_dict(event).get("payload") or {}


def recovery_plan(*, failure_event, registry):
    """Map a failure kind to a registered action; an unmapped kind raises `NoRecoveryPath`."""
    if not isinstance(registry, dict):
        raise ValueError("registry must be a mapping of {failure_kind: action}")
    kind = _field(failure_event, "kind")
    if kind != "first_failure":
        raise ValueError(
            "recovery_plan expects a first_failure event, got %r" % (kind,))
    payload = _payload(failure_event)
    failure_kind = payload.get("failure_kind") or payload.get("invariant")
    if not failure_kind:
        failure_kind = kind
    if failure_kind not in registry:
        raise NoRecoveryPath(
            "no recovery action registered for failure kind %r: an unmapped failure is not "
            "silently defaulted" % (failure_kind,), failure_kind=failure_kind)
    rollback = rollback_pointer(workorder_id=_field(failure_event, "workorder_id"),
                                baseline_sha=_field(failure_event, "subject_sha"))
    return {
        "schema": RECOVERY_PLAN_SCHEMA,
        "failure_kind": failure_kind,
        "recovery_action": registry[failure_kind],
        "rollback_pointer": rollback,
        "workorder_id": _field(failure_event, "workorder_id"),
        "checkpoint_id": _field(failure_event, "checkpoint_id"),
        "seq": _field(failure_event, "seq"),
    }


def first_failing_invariant(events):
    """The invariant named by the EARLIEST first_failure event, or None if none exists."""
    candidates = []
    for event in events or ():
        source = _as_dict(event)
        if source.get("kind") != "first_failure":
            continue
        seq = source.get("seq")
        candidates.append((seq if seq is not None else 0, _payload(event)))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1].get("invariant")


def _signature(event):
    source = _as_dict(event)
    payload = _payload(event)
    signature = {
        "seq": source.get("seq"),
        "kind": source.get("kind"),
        "trace_id": _field(source, "trace_id"),
        "workorder_id": _field(source, "workorder_id"),
        "checkpoint_id": _field(source, "checkpoint_id"),
        "subject_id": _field(source, "subject_id"),
        "subject_sha": _field(source, "subject_sha"),
        "invariant": payload.get("invariant"),
        "recovery_action": payload.get("recovery_action"),
    }
    return {name: signature[name] for name in SIG_KEYS}


def deterministic_readback(events):
    """A pure, order-normalised readback of the events (same events => identical bytes)."""
    rows = [_signature(event) for event in events or ()]
    rows.sort(key=lambda row: (row["seq"] is None, row["seq"], str(row["kind"])))
    return rows