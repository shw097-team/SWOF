"""Focused tests: trust facets are orthogonal; no resurrection. PI-PKG-05."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from knowledge.trust import (  # noqa: E402
    EligibilityDecision, Freshness, OrthogonalFacetViolation, Provenance, ResurrectionRefused,
    Revocation, Rights, SourceFabric, SourceValidityVector, evaluate_eligibility, refuse_collapse,
)


def vec(**kw):
    base = dict(rights=Rights.GRANTED, freshness=Freshness.CURRENT, revocation=Revocation.LIVE,
                provenance=Provenance.VERIFIED, generation=1, purpose="research")
    base.update(kw)
    return SourceValidityVector(**base)


class TestEligibility(unittest.TestCase):
    def test_available_but_not_eligible_rights_denied(self):
        d = evaluate_eligibility(vec(rights=Rights.DENIED), use_class="Q", required_purpose="research")
        self.assertFalse(d.eligible); self.assertIn("rights", d.reason)

    def test_available_but_not_eligible_stale(self):
        self.assertFalse(evaluate_eligibility(vec(freshness=Freshness.STALE), use_class="Q",
                                              required_purpose="research").eligible)

    def test_available_but_not_eligible_revoked(self):
        self.assertFalse(evaluate_eligibility(vec(revocation=Revocation.REVOKED), use_class="Q",
                                              required_purpose="research").eligible)

    def test_all_facets_pass_is_eligible(self):
        self.assertTrue(evaluate_eligibility(vec(), use_class="Q", required_purpose="research").eligible)

    def test_purpose_laundering_refused(self):
        """PI-PKG-05 18.1: a research grant reused for another purpose must DENY."""
        self.assertFalse(evaluate_eligibility(vec(purpose="research"), use_class="Q",
                                              required_purpose="training").eligible)


class TestOrthogonality(unittest.TestCase):
    def test_revoked_as_stale_is_rejected(self):
        with self.assertRaises(OrthogonalFacetViolation) as c:
            refuse_collapse(vec(revocation=Revocation.REVOKED, freshness=Freshness.CURRENT),
                            claimed_freshness=Freshness.STALE)
        self.assertEqual(c.exception.code, "ORTHOGONAL_TRUST_FACETS")

    def test_genuine_stale_is_not_rejected(self):
        refuse_collapse(vec(freshness=Freshness.STALE), claimed_freshness=Freshness.STALE)  # no raise


class TestNoResurrection(unittest.TestCase):
    def setUp(self):
        self.f = SourceFabric(); self.f.put("s1", vec(generation=1)); self.f.index("s1", 1)

    def test_revoked_generation_cannot_be_retrieved(self):
        self.f.revoke("s1", reason="rights revoked")
        with self.assertRaises(ResurrectionRefused) as c:
            self.f.retrieve("s1", 1)
        self.assertEqual(c.exception.code, "RESURRECTION_REFUSED")

    def test_revoked_generation_cannot_be_reindexed(self):
        self.f.revoke("s1")
        with self.assertRaises(ResurrectionRefused):
            self.f.index("s1", 1)

    def test_stale_as_current_generation_refused(self):
        self.f.put("s2", vec(generation=5))
        with self.assertRaises(Exception):
            self.f.retrieve("s2", 4)


if __name__ == "__main__":
    unittest.main()
