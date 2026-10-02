"""Focused tests: the four objects are orthogonal and none promotes to authority."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from knowledge.retrieval import (  # noqa: E402
    CandidateEnvelope, GroundingDefect, GroundingResult, RetrievalEvaluation, RetrievalPlan,
    ScopeWidening,
)


class TestRetrievalObjects(unittest.TestCase):
    def test_plan_scope_may_not_widen(self):
        with self.assertRaises(ScopeWidening) as c:
            RetrievalPlan("P1", "Q1", "EXACT_ID", "research", frozenset({"a"}), frozenset({"a", "b"})).validate()
        self.assertEqual(c.exception.code, "SCOPE_WIDENING")

    def test_plan_scope_subset_is_allowed(self):
        p = RetrievalPlan("P1", "Q1", "EXACT_ID", "research", frozenset({"a", "b"}), frozenset({"a"}))
        self.assertEqual(p.validate().state, "PLAN_VALIDATED")

    def test_high_score_ineligible_candidate_cannot_ground(self):
        c = CandidateEnvelope("C1", "s1", 1, 0.99, "loc", eligible=False)
        with self.assertRaises(GroundingDefect) as e:
            c.as_grounding_input()
        self.assertIn("RETRIEVED but not ELIGIBLE", str(e.exception))

    def test_grounded_answer_is_not_an_acceptance(self):
        g = GroundingResult("G1", claims=["c1"], witnesses={"c1": "w1"}).ground()
        self.assertEqual(g.state, "GROUNDED")
        with self.assertRaises(GroundingDefect):
            g.as_acceptance()

    def test_ungrounded_when_witness_missing(self):
        self.assertEqual(GroundingResult("G2", claims=["c1"], witnesses={}).ground().state, "UNGROUNDED")

    def test_retrieval_evaluation_is_not_package_assurance(self):
        with self.assertRaises(GroundingDefect):
            RetrievalEvaluation("E1", "subj").as_package_assurance()


if __name__ == "__main__":
    unittest.main()
