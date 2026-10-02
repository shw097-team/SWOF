"""Focused tests: the four objects are orthogonal and none promotes to authority."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from knowledge.retrieval import (  # noqa: E402
    CandidateEnvelope as _CE,
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

    def test_caller_asserted_ineligibility_is_refused_first(self):
        """R-2: a caller-asserted eligibility flag is refused before the ineligible branch can be trusted."""
        c = CandidateEnvelope("C1", "s1", 1, 0.99, "loc", eligible=False)
        with self.assertRaises(GroundingDefect) as e:
            c.as_grounding_input()
        self.assertIn("CALLER-ASSERTED", str(e.exception))

    def test_high_score_ineligible_candidate_cannot_ground(self):
        """A high-scoring candidate whose eligibility is DERIVED as ineligible still cannot ground."""
        from knowledge.trust import Freshness, Provenance, Revocation, Rights, SourceValidityVector
        v = SourceValidityVector(rights=Rights.DENIED, freshness=Freshness.CURRENT,
                                 revocation=Revocation.LIVE, provenance=Provenance.VERIFIED, generation=1)
        c = CandidateEnvelope.from_trust(candidate_id="C1", source_id="s1", generation=1, score=0.99,
                                         locator="loc", validity=v, use_class="Q", required_purpose="")
        self.assertFalse(c.eligible)
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


    def test_caller_asserted_eligibility_refuses_grounding(self):
        """R-2: eligibility must be DERIVED from trust facets, not asserted by the caller."""
        c = _CE("C9", "s1", 1, 0.99, "loc", eligible=True)
        with self.assertRaises(GroundingDefect) as e:
            c.as_grounding_input()
        self.assertIn("CALLER-ASSERTED", str(e.exception))

    def test_trust_derived_eligibility_allows_grounding(self):
        from knowledge.trust import Freshness, Provenance, Revocation, Rights, SourceValidityVector
        from knowledge.retrieval import CandidateEnvelope
        v = SourceValidityVector(rights=Rights.GRANTED, freshness=Freshness.CURRENT,
                                 revocation=Revocation.LIVE, provenance=Provenance.VERIFIED,
                                 generation=1, purpose="research")
        c = CandidateEnvelope.from_trust(candidate_id="C10", source_id="s1", generation=1, score=0.5,
                                         locator="loc", validity=v, use_class="Q",
                                         required_purpose="research")
        self.assertTrue(c.eligible)
        self.assertTrue(c.eligibility_source.startswith("TRUST_DERIVED:"))
        c.as_grounding_input()  # must not raise

    def test_trust_derived_ineligible_cannot_ground(self):
        from knowledge.trust import Freshness, Provenance, Revocation, Rights, SourceValidityVector
        from knowledge.retrieval import CandidateEnvelope
        v = SourceValidityVector(rights=Rights.DENIED, freshness=Freshness.CURRENT,
                                 revocation=Revocation.LIVE, provenance=Provenance.VERIFIED, generation=1)
        c = CandidateEnvelope.from_trust(candidate_id="C11", source_id="s2", generation=1, score=0.99,
                                         locator="loc", validity=v, use_class="Q", required_purpose="")
        self.assertFalse(c.eligible)
        with self.assertRaises(GroundingDefect):
            c.as_grounding_input()


if __name__ == "__main__":
    unittest.main()
