"""Tests: first-failure verdicts, undefined oracles, and unrepresented negative fixtures."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from assurance.oracle import (  # noqa: E402
    CHECK_ORDER, Oracle, OracleAmbiguous, OracleVerdict, verdict_digest,
)
from assurance.predicate import validate  # noqa: E402

ORACLE_ID = "ORACLE.SWOF.STD/1"


def predicate(**overrides):
    base = {
        "predicate_id": "PRED-1",
        "subject_id": "SUBJ-1",
        "subject_type": "DELIVERABLE",
        "required_evidence_kinds": frozenset({"TEST_RUN"}),
        "oracle_id": ORACLE_ID,
        "terminal_states": ("PASS", "FAIL"),
        "negative_fixtures": ("NEG-1",),
    }
    base.update(overrides)
    return validate(base)


def item(kind="TEST_RUN", item_id="item-1", subject_id="SUBJ-1", negative_fixtures=("NEG-1",)):
    return {
        "item_id": item_id,
        "kind": kind,
        "subject_id": subject_id,
        "sha256": "a" * 64,
        "negative_fixtures": negative_fixtures,
    }


class TestDefinedOracle(unittest.TestCase):
    def test_required_kinds_come_from_rules(self):
        self.assertIn("TEST_RUN", Oracle(ORACLE_ID).required_kinds())

    def test_undefined_oracle_is_ambiguous(self):
        with self.assertRaises(OracleAmbiguous) as ctx:
            Oracle("ORACLE.DOES.NOT.EXIST/9").required_kinds()
        self.assertEqual(OracleAmbiguous.code, "ERR_ORACLE_AMBIGUOUS")
        self.assertEqual(ctx.exception.reason_code, "ORACLE_UNDEFINED")

    def test_undefined_oracle_cannot_decide(self):
        with self.assertRaises(OracleAmbiguous):
            Oracle("ORACLE.DOES.NOT.EXIST/9").decide(predicate(oracle_id="ORACLE.DOES.NOT.EXIST/9"),
                                                     [item()])


class TestFirstFailure(unittest.TestCase):
    def test_passing_verdict(self):
        verdict = Oracle(ORACLE_ID).decide(predicate(), [item()])
        self.assertIsInstance(verdict, OracleVerdict)
        self.assertTrue(verdict.passed)
        self.assertIsNone(verdict.first_failure)
        self.assertEqual(verdict.reason_code, "PASS")

    def test_missing_kind_is_named_first(self):
        verdict = Oracle(ORACLE_ID).decide(predicate(), [item(kind="OTHER")])
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.first_failure, "MISSING_EVIDENCE_KIND")
        self.assertEqual(verdict.reason_code, "MISSING_EVIDENCE_KIND")

    def test_duplicate_kind_is_distinct(self):
        items = [item(item_id="item-1"), item(item_id="item-2")]
        verdict = Oracle(ORACLE_ID).decide(predicate(), items)
        self.assertEqual(verdict.reason_code, "DUPLICATE_EVIDENCE_KIND")

    def test_wrong_subject_is_distinct(self):
        verdict = Oracle(ORACLE_ID).decide(predicate(), [item(subject_id="SUBJ-OTHER")])
        self.assertEqual(verdict.reason_code, "WRONG_SUBJECT")

    def test_non_deterministic_order_is_distinct(self):
        items = [item(item_id="item-2"), item(item_id="item-1")]
        verdict = Oracle(ORACLE_ID).decide(predicate(), items)
        self.assertEqual(verdict.reason_code, "NON_DETERMINISTIC_ORDER")

    def test_reason_codes_are_all_reachable_and_distinct(self):
        seen = {
            Oracle(ORACLE_ID).decide(predicate(), [item(kind="OTHER")]).reason_code,
            Oracle(ORACLE_ID).decide(predicate(), [item(item_id="a"), item(item_id="b")]).reason_code,
            Oracle(ORACLE_ID).decide(predicate(), [item(subject_id="S")]).reason_code,
            Oracle(ORACLE_ID).decide(predicate(), [item(item_id="b"), item(item_id="a")]).reason_code,
            Oracle(ORACLE_ID).decide(predicate(), [item()]).reason_code,
        }
        self.assertEqual(seen, {"MISSING_EVIDENCE_KIND", "DUPLICATE_EVIDENCE_KIND",
                                "WRONG_SUBJECT", "NON_DETERMINISTIC_ORDER", "PASS"})


class TestNegativeRepresentation(unittest.TestCase):
    def test_unrepresented_negative_fixture_does_not_pass(self):
        verdict = Oracle(ORACLE_ID).decide(predicate(), [item(negative_fixtures=())])
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.reason_code, "NEGATIVE_FIXTURE_UNREPRESENTED")

    def test_represented_negative_fixture_passes(self):
        verdict = Oracle(ORACLE_ID).decide(predicate(), [item(negative_fixtures=("NEG-1",))])
        self.assertTrue(verdict.passed)


class TestPurity(unittest.TestCase):
    def test_identical_inputs_give_identical_verdicts(self):
        first = Oracle(ORACLE_ID).decide(predicate(), [item(item_id="a"), item(item_id="b")])
        second = Oracle(ORACLE_ID).decide(predicate(), [item(item_id="a"), item(item_id="b")])
        self.assertEqual(first, second)
        self.assertEqual(verdict_digest(first), verdict_digest(second))

    def test_checked_and_failures_are_ordered(self):
        items = [item(item_id="a", kind="OTHER_A"), item(item_id="b", kind="OTHER_B")]
        verdict = Oracle(ORACLE_ID).decide(predicate(), items)
        self.assertEqual(verdict.checked, tuple(sorted(verdict.checked)))
        self.assertEqual(verdict.failures, tuple(sorted(verdict.failures)))

    def test_check_order_documents_the_ladder(self):
        self.assertEqual(CHECK_ORDER[0], "PREDICATE_INVALID")
        self.assertLess(CHECK_ORDER.index("ORACLE_AMBIGUOUS"),
                        CHECK_ORDER.index("MISSING_EVIDENCE_KIND"))

    def test_invalid_predicate_yields_verdict_not_exception(self):
        verdict = Oracle(ORACLE_ID).decide({"predicate_id": ""}, [item()])
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.first_failure, "PREDICATE_INVALID")


if __name__ == "__main__":
    unittest.main()