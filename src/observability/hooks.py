"""Hook bus: the ordered, redacted event stream the rest of W2 emits into.

WHY: W2 must be able to PROVE what happened. The bus is the single place events are ordered,
redacted and retained, so the properties are structural rather than per-call-site discipline:

1. an unknown kind is refused (fail closed) and `seq` is assigned by the bus - contiguous from
   1 - so a caller can neither invent a kind nor forge an ordering;
2. EVERY payload is redacted through `redaction.redact_event` BEFORE it is stored, and the
   redaction receipt is recorded inside the event under `_redaction`. A secret therefore never
   enters the stream, not even transiently;
3. the FIRST `first_failure` event is retained forever. A first failure is evidence; a later
   recovery does not erase it (this is the whole point of first-failure semantics);
4. `replay()` is a pure, byte-stable readback: calling it twice yields identical output, so an
   independent party can re-derive the same sequence;
5. the sink receives ONLY the redacted line - the raw payload is never handed to a sink.

The bus observes; it does not judge. An event is not evidence of world-state success.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from observability.correlation import CorrelationContext, assert_bound, key
from observability.redaction import assert_log_safe, redact_event, redact_line

EVENT_ORDER = (
    "trace_start",
    "workorder_state",
    "checkpoint",
    "first_failure",
    "recovery",
    "rollback",
    "evidence_invalidation",
    "subject_bound",
)

EVENT_KINDS = frozenset(EVENT_ORDER)


class UnknownEventKind(Exception):
    """An emit() used an event kind that is not in the declared vocabulary."""

    code = "ERR_UNKNOWN_EVENT_KIND"

    def __init__(self, message, kind=None):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Event:
    seq: int
    kind: str
    correlation: CorrelationContext
    payload: dict
    emitted_at: str


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class HookBus:
    """An append-only, redacting event bus with deterministic readback."""

    def __init__(self, *, sink=None):
        if sink is not None and not callable(sink):
            raise ValueError("sink must be callable or None")
        self._sink = sink
        self._events = []
        self._first_failure = None
        self._seq = 0

    def emit(self, kind, *, correlation, payload=None, emitted_at=None):
        if kind not in EVENT_KINDS:
            raise UnknownEventKind(
                "unknown event kind %r: the vocabulary is closed and fails closed "
                "(an untyped event cannot be replayed)" % (kind,), kind=kind)
        assert_bound(correlation)
        if payload is None:
            payload = {"kind": kind}
        if not isinstance(payload, dict):
            raise ValueError("event payload must be a mapping, got %s" % type(payload).__name__)
        clean, receipt = redact_event(payload)
        stored = dict(clean)
        stored["_redaction"] = receipt
        self._seq += 1
        event = Event(seq=self._seq, kind=kind, correlation=correlation, payload=stored,
                      emitted_at=emitted_at if emitted_at is not None else _utcnow())
        self._events.append(event)
        if kind == "first_failure" and self._first_failure is None:
            self._first_failure = event
        self._to_sink(event)
        return event

    def _to_sink(self, event):
        if self._sink is None:
            return
        line_payload = {
            "seq": event.seq,
            "kind": event.kind,
            "trace_id": event.correlation.trace_id,
            "workorder_id": event.correlation.workorder_id,
            "checkpoint_id": event.correlation.checkpoint_id,
            "subject_id": event.correlation.subject_id,
            "subject_sha": event.correlation.subject_sha,
            "correlation_key": key(event.correlation),
            "emitted_at": event.emitted_at,
            "payload": event.payload,
        }
        rendered = json.dumps(line_payload, sort_keys=True, ensure_ascii=True, default=str)
        safe_line, _ = redact_line(rendered)
        assert_log_safe(safe_line)
        self._sink(safe_line)

    def events(self):
        return tuple(self._events)

    def first_failure(self):
        return self._first_failure

    def replay(self):
        return [
            {
                "seq": event.seq,
                "kind": event.kind,
                "trace_id": event.correlation.trace_id,
                "workorder_id": event.correlation.workorder_id,
                "checkpoint_id": event.correlation.checkpoint_id,
                "subject_id": event.correlation.subject_id,
                "payload": copy.deepcopy(event.payload),
            }
            for event in sorted(self._events, key=lambda item: item.seq)
        ]

    def tally(self):
        counts = {}
        for event in self._events:
            counts[event.kind] = counts.get(event.kind, 0) + 1
        return {kind: counts[kind] for kind in EVENT_ORDER if kind in counts}