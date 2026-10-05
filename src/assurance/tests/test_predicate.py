"""Tests: the predicate must be falsifiable, validated on raw input, and stably digested."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from assurance.predicate import (  # noqa: E402
    SUBJECT_TYPES, AcceptancePredicate, PredicateInvalid, digest, validate,
)


def make_predicate(**overrides):
    base = {
        "predicate_id": "PRED-1",
        "subject_id": "SUBJ-1",
        "subject_type": "DELIVERABLE",
        "required_evidence_kinds": frozenset({"TEST_RUN"}),
        "oracle_id": "ORACLE.SWOF.STD/1",
        "terminal_states": ("PASS", "FAIL"),
        "negative_fixtures": ("NEG-1",),
    }
    base.update(overrides)
    return base


class TestValidPredicate(unittest.TestCase):
    def test_validate_returns_immutable_predicate(self):
        predicate = validate(make_predicate())
        self.assertIsInstance(predicate, AcceptancePredicate)
        self.assertEqual(predicate.predicate_id, "PRED-1")
        self.assertIsInstance(predicate.required_evidence_kinds, frozenset)
        self.assertEqual(predicate.terminal_states, ("PASS", "FAIL"))

    def test_defaults_are_fail_closed(self):
        predicate = validate(make_predicate())
        self.assertTrue(predicate.raw_evidence_required)
        self.assertTrue(predicate.independent_checker_required)

    def test_every_subject_type_is_accepted(self):
        for subject_type in SUBJECT_TYPES:
            self.assertEqual(validate(make_predicate(subject_type=subject_type)).subject_type,
                             subject_type)


class TestUnfalsifiableRefusals(unittest.TestCase):
    def test_empty_predicate_is_invalid(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate({})
        self.assertEqual(PredicateInvalid.code, "ERR_PREDICATE_INVALID")
        self.assertEqual(ctx.exception.reason_code, "MISSING_PREDICATE_ID")

    def test_empty_oracle_id_is_invalid(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(oracle_id=""))
        self.assertEqual(ctx.exception.reason_code, "MISSING_ORACLE_ID")

    def test_empty_required_evidence_kinds_is_invalid(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(required_evidence_kinds=frozenset()))
        self.assertEqual(ctx.exception.reason_code, "EMPTY_REQUIRED_EVIDENCE_KINDS")

    def test_empty_negative_fixtures_is_invalid(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(negative_fixtures=()))
        self.assertEqual(ctx.exception.reason_code, "EMPTY_NEGATIVE_FIXTURES")

    def test_unknown_subject_type_is_invalid(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(subject_type="MADE_UP"))
        self.assertEqual(ctx.exception.reason_code, "UNKNOWN_SUBJECT_TYPE")

    def test_single_terminal_state_is_invalid(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(terminal_states=("PASS",)))
        self.assertEqual(ctx.exception.reason_code, "TOO_FEW_TERMINAL_STATES")


class TestRawValidationBeforeConstruction(unittest.TestCase):
    def test_none_raises_typed_not_type_error(self):
        with self.assertRaises(PredicateInvalid):
            validate(None)

    def test_non_collection_kinds_raises_typed(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(required_evidence_kinds=42))
        self.assertEqual(ctx.exception.reason_code, "REQUIRED_EVIDENCE_KINDS_NOT_A_COLLECTION")

    def test_non_sequence_terminal_states_raises_typed(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate(make_predicate(terminal_states="PASS"))
        self.assertEqual(ctx.exception.reason_code, "TERMINAL_STATES_NOT_A_SEQUENCE")


class TestDigest(unittest.TestCase):
    def test_digest_is_stable_and_semantic_only(self):
        predicate = validate(make_predicate())
        self.assertEqual(digest(predicate), digest(predicate))
        self.assertEqual(len(digest(predicate)), 64)

    def test_runtime_binding_fields_do_not_change_digest(self):
        first = dict(make_predicate())
        first["plan_id"] = "PLAN-A"
        first["environment"] = "ENV-A"
        second = dict(make_predicate())
        second["plan_id"] = "PLAN-B"
        second["environment"] = "ENV-B"
        self.assertEqual(digest(validate(first)), digest(validate(second)))

    def test_semantic_change_changes_digest(self):
        base = digest(validate(make_predicate()))
        other = digest(validate(make_predicate(oracle_id="ORACLE.SWOF.W2-ASSURANCE/1")))
        self.assertNotEqual(base, other)

    def test_digest_accepts_a_mapping(self):
        self.assertEqual(digest(make_predicate()), digest(validate(make_predicate())))


if __name__ == "__main__":
    unittest.main()