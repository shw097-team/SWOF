"""Acceptance predicates: the decidable, falsifiable unit of SWOF assurance.

A predicate is the *only* place a PASS/FAIL question is defined. The law this module
enforces is one line:

    a predicate that cannot fail is not a predicate.

So an empty oracle, an empty evidence requirement, an empty negative-fixture set, an
unknown subject type or a terminal-state set with fewer than two members are all refused
with a typed `PredicateInvalid` carrying a specific `reason_code`, and validation happens
on the RAW input *before* anything is constructed, so malformed input never leaks a
generic `TypeError`.

`digest` covers immutable semantic content only. Runtime binding state (the plan, the
environment, the run) is deliberately excluded, so two predicates that differ only in a
runtime field cannot collide and the same predicate always digests the same.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

SUBJECT_TYPES = ("DELIVERABLE", "CAPABILITY", "JOURNEY", "REQUIREMENT")

DIGEST_DOMAIN = "swof.assurance.predicate.v1"

# The immutable semantic fields, in a documented, stable order. Runtime binding fields are
# NOT here: a predicate digest describes meaning, not the run in which it is checked.
_SEMANTIC_FIELDS = (
    "predicate_id",
    "subject_id",
    "subject_type",
    "required_evidence_kinds",
    "oracle_id",
    "terminal_states",
    "negative_fixtures",
    "raw_evidence_required",
    "independent_checker_required",
)


class PredicateInvalid(Exception):
    """A predicate that cannot fail (or is malformed) was refused."""

    code = "ERR_PREDICATE_INVALID"

    def __init__(self, message, reason_code="PREDICATE_INVALID"):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class AcceptancePredicate:
    predicate_id: str
    subject_id: str
    subject_type: str
    required_evidence_kinds: frozenset
    oracle_id: str
    terminal_states: tuple
    negative_fixtures: tuple
    raw_evidence_required: bool = True
    independent_checker_required: bool = True


def _field(raw, name, default=None):
    if isinstance(raw, dict):
        return raw.get(name, default)
    return getattr(raw, name, default)


def _is_nonempty_str(value):
    return isinstance(value, str) and value.strip() != ""


def _validate_raw(raw):
    if raw is None:
        raise PredicateInvalid("predicate is None", "PREDICATE_NONE")

    for name in ("predicate_id", "subject_id", "oracle_id"):
        if not _is_nonempty_str(_field(raw, name)):
            raise PredicateInvalid(
                "%s must be a non-empty string" % name, "MISSING_" + name.upper())

    subject_type = _field(raw, "subject_type")
    if subject_type not in SUBJECT_TYPES:
        raise PredicateInvalid(
            "unknown subject_type %r (known: %s)" % (subject_type, ", ".join(SUBJECT_TYPES)),
            "UNKNOWN_SUBJECT_TYPE")

    kinds = _field(raw, "required_evidence_kinds")
    if kinds is None or not isinstance(kinds, (frozenset, set, tuple, list)):
        raise PredicateInvalid(
            "required_evidence_kinds must be a collection, got %r" % (type(kinds).__name__,),
            "REQUIRED_EVIDENCE_KINDS_NOT_A_COLLECTION")
    if len(kinds) == 0:
        raise PredicateInvalid(
            "required_evidence_kinds is empty: a predicate with no required evidence "
            "cannot fail", "EMPTY_REQUIRED_EVIDENCE_KINDS")
    for kind in kinds:
        if not _is_nonempty_str(kind):
            raise PredicateInvalid(
                "required_evidence_kinds contains a non-string/empty entry %r" % (kind,),
                "MALFORMED_REQUIRED_EVIDENCE_KIND")

    terminal_states = _field(raw, "terminal_states")
    if terminal_states is None or not isinstance(terminal_states, (tuple, list)):
        raise PredicateInvalid(
            "terminal_states must be a sequence, got %r" % (type(terminal_states).__name__,),
            "TERMINAL_STATES_NOT_A_SEQUENCE")
    if len(terminal_states) < 2:
        raise PredicateInvalid(
            "terminal_states has %d state(s): fewer than two terminal states cannot "
            "express failure" % len(terminal_states), "TOO_FEW_TERMINAL_STATES")
    for state in terminal_states:
        if not _is_nonempty_str(state):
            raise PredicateInvalid(
                "terminal_states contains a non-string/empty entry %r" % (state,),
                "MALFORMED_TERMINAL_STATE")

    negative_fixtures = _field(raw, "negative_fixtures")
    if negative_fixtures is None or not isinstance(negative_fixtures, (tuple, list)):
        raise PredicateInvalid(
            "negative_fixtures must be a sequence, got %r"
            % (type(negative_fixtures).__name__,), "NEGATIVE_FIXTURES_NOT_A_SEQUENCE")
    if len(negative_fixtures) == 0:
        raise PredicateInvalid(
            "negative_fixtures is empty: a predicate whose negatives are never tested is "
            "not decidable", "EMPTY_NEGATIVE_FIXTURES")
    for fixture in negative_fixtures:
        if not _is_nonempty_str(fixture):
            raise PredicateInvalid(
                "negative_fixtures contains a non-string/empty entry %r" % (fixture,),
                "MALFORMED_NEGATIVE_FIXTURE")

    for name in ("raw_evidence_required", "independent_checker_required"):
        value = _field(raw, name, None)
        if value is not None and not isinstance(value, bool):
            raise PredicateInvalid(
                "%s must be a bool when present, got %r" % (name, value),
                "MALFORMED_FLAG_" + name.upper())


def validate(predicate):
    """Validate the RAW input and return an immutable AcceptancePredicate.

    The raw mapping/object is validated first, so a malformed input raises
    PredicateInvalid rather than a generic TypeError from constructing a dataclass.
    """
    _validate_raw(predicate)

    def _get(name, default=None):
        return _field(predicate, name, default)

    return AcceptancePredicate(
        predicate_id=_get("predicate_id"),
        subject_id=_get("subject_id"),
        subject_type=_get("subject_type"),
        required_evidence_kinds=frozenset(_get("required_evidence_kinds")),
        oracle_id=_get("oracle_id"),
        terminal_states=tuple(_get("terminal_states")),
        negative_fixtures=tuple(_get("negative_fixtures")),
        raw_evidence_required=bool(_get("raw_evidence_required", True)),
        independent_checker_required=bool(_get("independent_checker_required", True)),
    )


def _canonical_bytes(predicate):
    raw = predicate if isinstance(predicate, dict) else None
    if raw is None:
        raw = {name: getattr(predicate, name) for name in _SEMANTIC_FIELDS}
    else:
        missing = [name for name in _SEMANTIC_FIELDS if name not in raw]
        if missing:
            raise PredicateInvalid(
                "predicate mapping is missing semantic fields %s" % (missing,),
                "MISSING_SEMANTIC_FIELDS")
    material = {name: raw[name] for name in _SEMANTIC_FIELDS}
    material["required_evidence_kinds"] = sorted(material["required_evidence_kinds"])
    material["terminal_states"] = list(material["terminal_states"])
    material["negative_fixtures"] = list(material["negative_fixtures"])
    canon = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return canon.encode("utf-8")


def digest(predicate):
    """Deterministic sha256 hex over the immutable semantic content of the predicate.

    Accepts an AcceptancePredicate or a validated mapping. Runtime binding state is
    excluded by construction, so it can never influence (or collide with) this digest.
    """
    if not isinstance(predicate, AcceptancePredicate):
        predicate = validate(predicate)
    payload = DIGEST_DOMAIN.encode("utf-8") + b"\x00" + _canonical_bytes(predicate)
    return hashlib.sha256(payload).hexdigest()