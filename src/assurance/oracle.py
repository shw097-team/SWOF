"""Oracles: the procedure that turns a predicate plus evidence items into a verdict.

An oracle is *defined* or it is not usable: an oracle_id with no registered rules raises
`OracleAmbiguous` rather than guessing. `decide` is FIRST-FAILURE: it walks a stable,
documented condition ladder and stops at the first failing condition, naming it in
`first_failure`. It never keeps collecting "nicer" failures in a way that would change the
verdict, and it never returns passed=True while any negative fixture declared by the
predicate is unrepresented in the checked set - an untested negative fixture means the
predicate is not yet decidable.

`OracleVerdict` is a pure function of (predicate, items): identical inputs produce
identical verdicts, including the order of `checked` and `failures`. Inputs are sorted by
a stable key, so no dict/set iteration order can leak into a decision.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from assurance.predicate import AcceptancePredicate, PredicateInvalid, validate

CHECK_ORDER = (
    "PREDICATE_INVALID",
    "ORACLE_AMBIGUOUS",
    "DUPLICATE_EVIDENCE_KIND",
    "WRONG_SUBJECT",
    "MISSING_EVIDENCE_KIND",
    "NON_DETERMINISTIC_ORDER",
    "NEGATIVE_FIXTURE_UNREPRESENTED",
)

# Rules are keyed by oracle_id. An id absent here is not decidable; see OracleAmbiguous.
_ORACLE_RULES = {
    "ORACLE.SWOF.STD/1": {
        "description": "the standard SWOF acceptance rule set",
        "kinds": ("TEST_RUN", "RAW_ARTIFACT", "HASH_PROOF", "COVERAGE_REPORT"),
        "require_kinds": True,
        "require_subject": True,
        "require_negative_representation": True,
    },
    "ORACLE.SWOF.W2-ASSURANCE/1": {
        "description": "the W2 assurance substrate rule set",
        "kinds": ("TEST_RUN", "RAW_ARTIFACT", "HASH_PROOF", "COVERAGE_REPORT",
                  "NEGATIVE_FIXTURE_PROOF"),
        "require_kinds": True,
        "require_subject": True,
        "require_negative_representation": True,
    },
}


class OracleAmbiguous(Exception):
    """The oracle_id does not name a defined rule set; no verdict can be produced."""

    code = "ERR_ORACLE_AMBIGUOUS"

    def __init__(self, message, reason_code="ORACLE_AMBIGUOUS"):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class OracleVerdict:
    passed: bool
    first_failure: str
    checked: tuple
    failures: tuple
    reason_code: str


def _item_field(item, name, default=None):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _item_key(item):
    return (
        str(_item_field(item, "kind", "")),
        str(_item_field(item, "item_id", "")),
        str(_item_field(item, "sha256", "")),
    )


def _negative_fixtures_of(item):
    raw = _item_field(item, "negative_fixtures", None)
    if raw is None:
        raw = _item_field(item, "negative_cases", None)
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    return tuple(sorted(str(x) for x in raw))


def _validate_items_shape(items):
    if items is None:
        raise OracleAmbiguous("items is None; nothing to decide", "ITEMS_NONE")
    if isinstance(items, (str, bytes, dict)):
        raise OracleAmbiguous(
            "items must be a sequence of evidence items, got %s" % type(items).__name__,
            "ITEMS_NOT_A_SEQUENCE")
    return list(items)


class Oracle:
    def __init__(self, oracle_id):
        self.oracle_id = oracle_id
        self._rules = _ORACLE_RULES.get(oracle_id)

    def required_kinds(self):
        if self._rules is None:
            raise OracleAmbiguous(
                "oracle %r has no defined rules" % (self.oracle_id,), "ORACLE_UNDEFINED")
        return frozenset(self._rules.get("kinds", ()))

    def decide(self, predicate, items):
        if isinstance(predicate, AcceptancePredicate):
            try:
                predicate = validate(predicate)
            except PredicateInvalid as exc:
                return OracleVerdict(
                    False, "PREDICATE_INVALID", (), (str(exc),),
                    "PREDICATE_INVALID_" + exc.reason_code)
        else:
            try:
                predicate = validate(predicate)
            except PredicateInvalid as exc:
                return OracleVerdict(
                    False, "PREDICATE_INVALID", (), (str(exc),),
                    "PREDICATE_INVALID_" + exc.reason_code)

        if self._rules is None:
            raise OracleAmbiguous(
                "oracle %r has no defined rules; an oracle that is not defined cannot "
                "decide" % (self.oracle_id,), "ORACLE_UNDEFINED")

        supplied = _validate_items_shape(items)
        # Detect a non-deterministic SUPPLIED ordering before sorting, so the input's own
        # instability is a distinct, reachable reason_code rather than being masked by sort.
        if supplied != sorted(supplied, key=_item_key):
            items = sorted(supplied, key=_item_key)
            checked = tuple(
                "%s|%s" % (_item_field(item, "kind", ""), _item_field(item, "item_id", ""))
                for item in items
            )
            return OracleVerdict(
                False, "NON_DETERMINISTIC_ORDER", checked,
                ("items were not supplied in a stable (kind, item_id, sha256) order",),
                "NON_DETERMINISTIC_ORDER")

        items = sorted(supplied, key=_item_key)
        checked = tuple(
            "%s|%s" % (_item_field(item, "kind", ""), _item_field(item, "item_id", ""))
            for item in items
        )

        kinds = [_item_field(item, "kind", None) for item in items]

        duplicates = sorted({k for k in kinds if kinds.count(k) > 1})
        if duplicates:
            return OracleVerdict(
                False, "DUPLICATE_EVIDENCE_KIND", checked,
                tuple("duplicate evidence kind %s" % k for k in duplicates),
                "DUPLICATE_EVIDENCE_KIND")

        required = set(predicate.required_evidence_kinds)
        wrong_subject = sorted(
            str(_item_field(item, "item_id", ""))
            for item in items
            if _item_field(item, "subject_id", None) != predicate.subject_id
        )
        if wrong_subject:
            return OracleVerdict(
                False, "WRONG_SUBJECT", checked,
                tuple("item %s has subject_id != %s" % (i, predicate.subject_id)
                      for i in wrong_subject),
                "WRONG_SUBJECT")

        missing = sorted(required - set(kinds))
        if missing:
            return OracleVerdict(
                False, "MISSING_EVIDENCE_KIND", checked,
                tuple("missing required evidence kind %s" % k for k in missing),
                "MISSING_EVIDENCE_KIND")


        represented = set()
        for item in items:
            represented.update(_negative_fixtures_of(item))
        unrepresented = sorted(set(predicate.negative_fixtures) - represented)
        if unrepresented and self._rules.get("require_negative_representation", True):
            return OracleVerdict(
                False, "NEGATIVE_FIXTURE_UNREPRESENTED", checked,
                tuple("negative fixture %s is unrepresented in the checked set" % f
                      for f in unrepresented),
                "NEGATIVE_FIXTURE_UNREPRESENTED")

        return OracleVerdict(True, None, checked, (), "PASS")


def verdict_digest(verdict):
    """Deterministic digest of a verdict, for evidence binding."""
    material = "|".join([
        "1" if verdict.passed else "0",
        verdict.first_failure or "",
        verdict.reason_code,
        ",".join(verdict.checked),
        ",".join(verdict.failures),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()