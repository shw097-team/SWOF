"""Focused tests: the four-part correlation identity and refusal of foreign evidence."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from effect.correlation import (  # noqa: E402
    CorrelationMismatch, WrongSubjectEvidence, bind_evidence, correlation_id,
    verify_correlation,
)
from effect.substrate import intend  # noqa: E402


def record(effect_id="eff-1", subject_id="subj-1"):
    return intend(effect_id, subject_id, {"op": "create"}, environment="test")


class TestCorrelationId(unittest.TestCase):
    def test_deterministic(self):
        base = correlation_id("eff-1", "subj-1", "digest", "test")
        self.assertEqual(base, correlation_id("eff-1", "subj-1", "digest", "test"))
        self.assertEqual(len(base), 64)

    def test_depends_on_all_four_inputs(self):
        base = correlation_id("eff-1", "subj-1", "digest", "test")
        self.assertNotEqual(base, correlation_id("eff-2", "subj-1", "digest", "test"))
        self.assertNotEqual(base, correlation_id("eff-1", "subj-2", "digest", "test"))
        self.assertNotEqual(base, correlation_id("eff-1", "subj-1", "other", "test"))
        self.assertNotEqual(base, correlation_id("eff-1", "subj-1", "digest", "prod"))

    def test_blank_input_is_refused(self):
        with self.assertRaises(ValueError):
            correlation_id("", "subj-1", "digest", "test")


class TestBindEvidence(unittest.TestCase):
    def test_binding_carries_exact_identity(self):
        rec = record()
        cid = correlation_id(rec.effect_id, rec.subject_id, rec.intent_digest,
                             rec.environment)
        binding = bind_evidence(rec, "evidence-1", evidence_subject_id="subj-1",
                                evidence_correlation_id=cid)
        self.assertEqual(binding["effect_id"], "eff-1")
        self.assertEqual(binding["subject_id"], "subj-1")
        self.assertEqual(binding["correlation_id"], cid)
        self.assertEqual(binding["evidence_ref"], "evidence-1")
        self.assertTrue(binding["subject_match"])

    def test_wrong_subject_is_refused(self):
        rec = record()
        cid = correlation_id(rec.effect_id, rec.subject_id, rec.intent_digest,
                             rec.environment)
        with self.assertRaises(WrongSubjectEvidence) as ctx:
            bind_evidence(rec, "evidence-1", evidence_subject_id="subj-2",
                          evidence_correlation_id=cid)
        self.assertEqual(WrongSubjectEvidence.code, "ERR_WRONG_SUBJECT_EVIDENCE")

    def test_correlation_mismatch_is_refused(self):
        with self.assertRaises(CorrelationMismatch) as ctx:
            bind_evidence(record(), "evidence-1", evidence_subject_id="subj-1",
                          evidence_correlation_id="not-the-id")
        self.assertEqual(CorrelationMismatch.code, "ERR_CORRELATION_MISMATCH")

    def test_wrong_effect_via_correlation_is_refused(self):
        other = record(effect_id="eff-2")
        other_cid = correlation_id(other.effect_id, other.subject_id, other.intent_digest,
                                   other.environment)
        with self.assertRaises(CorrelationMismatch):
            bind_evidence(record(), "evidence-1", evidence_subject_id="subj-1",
                          evidence_correlation_id=other_cid)


class TestVerifyCorrelation(unittest.TestCase):
    def test_verify_bound_evidence(self):
        rec = record()
        cid = correlation_id(rec.effect_id, rec.subject_id, rec.intent_digest,
                             rec.environment)
        binding = bind_evidence(rec, "evidence-1", evidence_subject_id="subj-1",
                                evidence_correlation_id=cid)
        self.assertEqual(verify_correlation(rec, binding),
                         {"bound": True, "reason_code": "BOUND"})

    def test_verify_wrong_subject(self):
        rec = record()
        result = verify_correlation(rec, {"subject_id": "subj-2", "correlation_id": "x",
                                          "effect_id": "eff-1"})
        self.assertFalse(result["bound"])
        self.assertEqual(result["reason_code"], "WRONG_SUBJECT_EVIDENCE")

    def test_verify_correlation_mismatch(self):
        rec = record()
        result = verify_correlation(rec, {"subject_id": "subj-1", "correlation_id": "x",
                                          "effect_id": "eff-1"})
        self.assertFalse(result["bound"])
        self.assertEqual(result["reason_code"], "CORRELATION_MISMATCH")

    def test_verify_malformed_evidence(self):
        self.assertEqual(verify_correlation(record(), "not-a-dict"),
                         {"bound": False, "reason_code": "MALFORMED_EVIDENCE"})


if __name__ == "__main__":
    unittest.main()
