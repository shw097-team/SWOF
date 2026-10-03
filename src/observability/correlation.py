"""Correlation identity: the five-part handle every event is bound to.

WHY: an event that cannot be tied to (trace, workorder, checkpoint, subject, subject revision)
cannot be replayed, and a replayed event that was silently re-pointed at another subject is a
substitution defect. Correlation is an IDENTITY, not an authority: it names what an observation
is about; it never proves the observation correct.

`derive` produces a child span of the SAME subject identity. It can move the trace, but it can
never re-point the subject, because an event emitted from one subject's span must not be
readable as another subject's evidence. `derive` therefore takes no subject parameter at all -
the refusal is structural, not a runtime check that could be skipped.

Laws:
- every field of a bound context is a non-empty string, else `CorrelationUnbound`;
- `derive` never changes `subject_id` or `subject_sha`;
- `key` is a stable digest over all five fields (the same identity always hashes the same way).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

FIELDS = ("trace_id", "workorder_id", "checkpoint_id", "subject_id", "subject_sha")

KEY_DOMAIN = "swof.observability.correlation.v1"


class CorrelationUnbound(Exception):
    """An event was not bound to a complete correlation identity."""

    code = "ERR_CORRELATION_UNBOUND"

    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class CorrelationContext:
    trace_id: str
    workorder_id: str
    checkpoint_id: str
    subject_id: str
    subject_sha: str


def _require(value, field):
    if not isinstance(value, str):
        raise CorrelationUnbound(
            "correlation field %s must be a string, got %s (fail closed: an unbound event is "
            "not observable)" % (field, type(value).__name__), field=field)
    if not value.strip():
        raise CorrelationUnbound(
            "correlation field %s must be non-empty (fail closed: a blank field identifies "
            "nothing and cannot be replayed)" % field, field=field)
    return value


def _trace_seed(*, workorder_id, checkpoint_id, subject_id, subject_sha):
    """A trace id derived from the identity, so it is deterministic without a clock."""
    material = "\x00".join([workorder_id, checkpoint_id, subject_id, subject_sha])
    return hashlib.sha256(
        (KEY_DOMAIN + "|trace\x00" + material).encode("utf-8")).hexdigest()[:32]


def new_context(*, workorder_id, checkpoint_id, subject_id, subject_sha, trace_id=None):
    """Build a bound correlation context; every field must be a non-empty string."""
    workorder_id = _require(workorder_id, "workorder_id")
    checkpoint_id = _require(checkpoint_id, "checkpoint_id")
    subject_id = _require(subject_id, "subject_id")
    subject_sha = _require(subject_sha, "subject_sha")
    if trace_id is None:
        trace_id = _trace_seed(workorder_id=workorder_id, checkpoint_id=checkpoint_id,
                               subject_id=subject_id, subject_sha=subject_sha)
    else:
        trace_id = _require(trace_id, "trace_id")
    return CorrelationContext(trace_id=trace_id, workorder_id=workorder_id,
                              checkpoint_id=checkpoint_id, subject_id=subject_id,
                              subject_sha=subject_sha)


def derive(context, *, suffix):
    """Child span of the SAME subject identity; cannot re-point the subject."""
    assert_bound(context)
    suffix = _require(suffix, "suffix")
    return replace(context, trace_id="%s.%s" % (context.trace_id, suffix))


def assert_bound(context):
    """Return the context if every field is bound, else raise `CorrelationUnbound`."""
    if not isinstance(context, CorrelationContext):
        raise CorrelationUnbound(
            "correlation context is %s, not a CorrelationContext" % type(context).__name__)
    for field in FIELDS:
        _require(getattr(context, field, None), field)
    return context


def key(context):
    """Stable digest over all five fields; the same identity always hashes the same."""
    assert_bound(context)
    material = "\x00".join(getattr(context, field) for field in FIELDS)
    return hashlib.sha256((KEY_DOMAIN + "\x00" + material).encode("utf-8")).hexdigest()