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


def _manifest_kinds(fixture_manifest, oracle_id, fixture):
    """The evidence KIND(S) the plan-level declaration binds to one negative fixture.

    The manifest is keyed by fixture id (optionally nested under the oracle id); each value is
    the evidence kind, or a collection of kinds, that genuinely represents the fixture. It may
    also be a callable taking the fixture id. A fixture the manifest does not name - or a
    manifest that is absent - has NO representation, so a self-declared field on an item can
    never supply one.
    """
    declared = None
    if isinstance(fixture_manifest, dict):
        table = fixture_manifest.get(oracle_id, fixture_manifest)
        if isinstance(table, dict):
            declared = table.get(fixture)
    elif callable(fixture_manifest):
        declared = fixture_manifest(fixture)
    if declared is None:
        return frozenset()
    if isinstance(declared, str):
        return frozenset({declared})
    if isinstance(declared, (frozenset, set, tuple, list)):
        return frozenset(str(x) for x in declared)
    return frozenset()


def _fixtures_declared_by_items(items):
    """The fixtures items CLAIM, collected only so the verdict can name the rejected claim.

    These are NOT proofs of representation; representation is derived from the evidence
    kinds/ids actually present. This is used to reject self-declared-but-unproven fixtures
    explicitly rather than silently ignoring the field.
    """
    claimed = set()
    for item in items:
        raw = _item_field(item, "negative_fixtures", None)
        if raw is None:
            raw = _item_field(item, "negative_cases", None)
        if raw is None:
            continue
        if isinstance(raw, str):
            claimed.add(raw)
        else:
            claimed.update(str(x) for x in raw)
    return claimed


def _validate_items_shape(items):
    if items is None:
        raise OracleAmbiguous("items is None; nothing to decide", "ITEMS_NONE")
    if isinstance(items, (str, bytes, dict)):
        raise OracleAmbiguous(
            "items must be a sequence of evidence items, got %s" % type(items).__name__,
            "ITEMS_NOT_A_SEQUENCE")
    return list(items)


class Oracle:
    def __init__(self, oracle_id, *, negative_fixture_manifest=None):
        self.oracle_id = oracle_id
        self._rules = _ORACLE_RULES.get(oracle_id)
        self._negative_fixture_manifest = negative_fixture_manifest

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


        if self._rules.get("require_negative_representation", True):
            manifest = self._negative_fixture_manifest
            present_kinds = {str(kind) for kind in kinds if kind is not None}
            present_ids = {str(_item_field(item, "item_id", "")) for item in items}
            claimed = _fixtures_declared_by_items(items)
            unrepresented = []
            for fixture in sorted(set(predicate.negative_fixtures)):
                proof_kinds = _manifest_kinds(manifest, self.oracle_id, fixture)
                proven = bool(proof_kinds & present_kinds) or fixture in present_ids
                if not proven:
                    unrepresented.append(fixture)
            if unrepresented:
                failures = []
                for fixture in unrepresented:
                    if fixture in claimed:
                        failures.append(
                            "negative fixture %s is self-declared on an item but not "
                            "represented by any evidence kind (a claim is not proof)" % fixture)
                    else:
                        failures.append(
                            "negative fixture %s is unrepresented by the checked evidence"
                            % fixture)
                return OracleVerdict(
                    False, "NEGATIVE_FIXTURE_UNREPRESENTED", checked, tuple(failures),
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
