"""Focused tests for the Search-Before-Build admission seam (PI-PKG-05 H1-05 / 19)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from admission.ladder import (  # noqa: E402
    LADDER, AdmissionDefect, CandidateDisposition, DowngradeRefused, PopularityNotQualification,
    SelectedIsNotInstalled, TechnologyAdmissionRegister, TechnologyRow, assert_anti_downgrade,
    assert_build_new_exception_allowed, choose_disposition, screen_popularity,
)


class TestLadder(unittest.TestCase):
    def test_ladder_order_matches_source(self):
        self.assertEqual(LADDER, ("REUSE", "WRAP", "TRANSLATE", "ADAPT", "COMPOSE",
                                  "BUILD_MINIMUM", "BUILD_NEW_EXCEPTION"))

    def test_strongest_non_failing_disposition_wins(self):
        c = choose_disposition([CandidateDisposition("REUSE", materially_fails=True, evidence_ref="e1"),
                                CandidateDisposition("WRAP"), CandidateDisposition("BUILD_NEW_EXCEPTION")])
        self.assertEqual(c.disposition, "WRAP")

    def test_build_minimum_requires_documented_material_gap(self):
        with self.assertRaises(AdmissionDefect):
            choose_disposition([CandidateDisposition("BUILD_MINIMUM", documented_material_gap="")])

    def test_build_minimum_allowed_with_gap(self):
        c = choose_disposition([CandidateDisposition("BUILD_MINIMUM", documented_material_gap="gap-1")])
        self.assertEqual(c.disposition, "BUILD_MINIMUM")

    def test_strongest_survivor_wins_over_build_new_exception(self):
        """The test was wrong: choose_disposition RETURNS the strongest surviving disposition."""
        c = choose_disposition([CandidateDisposition("REUSE", materially_fails=True, evidence_ref="e"),
                                CandidateDisposition("WRAP", materially_fails=False),
                                CandidateDisposition("BUILD_NEW_EXCEPTION")])
        self.assertEqual(c.disposition, "WRAP")

    def test_build_new_exception_refused_while_earlier_survives(self):
        """PI-PKG-05 19: requesting BUILD_NEW_EXCEPTION while an earlier disposition survives fails closed."""
        with self.assertRaises(AdmissionDefect) as c:
            assert_build_new_exception_allowed([
                CandidateDisposition("REUSE", materially_fails=True, evidence_ref="e"),
                CandidateDisposition("WRAP", materially_fails=False),
                CandidateDisposition("BUILD_NEW_EXCEPTION")])
        self.assertIn("still material", str(c.exception))

    def test_build_new_exception_allowed_when_all_earlier_fail(self):
        assert_build_new_exception_allowed([
            CandidateDisposition("REUSE", materially_fails=True, evidence_ref="e1"),
            CandidateDisposition("WRAP", materially_fails=True, evidence_ref="e2"),
            CandidateDisposition("TRANSLATE", materially_fails=True, evidence_ref="e3"),
            CandidateDisposition("ADAPT", materially_fails=True, evidence_ref="e4"),
            CandidateDisposition("COMPOSE", materially_fails=True, evidence_ref="e5"),
            CandidateDisposition("BUILD_MINIMUM", materially_fails=True, evidence_ref="e6"),
            CandidateDisposition("BUILD_NEW_EXCEPTION")])

    def test_anti_downgrade_refuses_weakening(self):
        with self.assertRaises(DowngradeRefused) as c:
            assert_anti_downgrade("OPA", "REUSE", "BUILD_NEW_EXCEPTION")
        self.assertEqual(c.exception.code, "ANTI_DOWNGRADE_REFUSED")

    def test_anti_downgrade_allows_strengthening(self):
        assert_anti_downgrade("OPA", "WRAP", "REUSE")  # no raise

    def test_popularity_is_not_qualification(self):
        with self.assertRaises(PopularityNotQualification) as c:
            screen_popularity(popularity_signal="50k stars", qualification_evidence="")
        self.assertEqual(c.exception.code, "POPULARITY_IS_NOT_QUALIFICATION")

    def test_popularity_ok_with_real_evidence(self):
        screen_popularity(popularity_signal="50k stars", qualification_evidence="qual-001")


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.reg = TechnologyAdmissionRegister()

    def test_selected_is_not_installed(self):
        self.reg.register(TechnologyRow("OPA_POLICY_EVAL", "OPA/Rego", "REUSE", selected=True, installed=False))
        with self.assertRaises(SelectedIsNotInstalled) as c:
            self.reg.activate("OPA_POLICY_EVAL")
        self.assertEqual(c.exception.code, "SELECTED_IS_NOT_INSTALLED")

    def test_rejected_technology_cannot_be_activated(self):
        self.reg.register(TechnologyRow("Cedar", "Cedar", "REUSE", selected=True, installed=True,
                                        qualified=True, rejected_for_primary_slot=True,
                                        provider_off="x", uninstall_exit="x", rollback="x", drift_trigger="x"))
        with self.assertRaises(AdmissionDefect):
            self.reg.activate("Cedar")

    def test_missing_provider_off_blocks_activation(self):
        self.reg.register(TechnologyRow("OpenLineage", "OL", "WRAP", selected=True, installed=True,
                                        qualified=True, provider_off="", uninstall_exit="x",
                                        rollback="x", drift_trigger="x"))
        with self.assertRaises(AdmissionDefect):
            self.reg.activate("OpenLineage")

    def test_full_row_activates(self):
        self.reg.register(TechnologyRow("OpenLineage", "OL", "WRAP", selected=True, installed=True,
                                        qualified=True, provider_off="off", uninstall_exit="drop",
                                        rollback="rb", drift_trigger="dt"))
        self.assertTrue(self.reg.activate("OpenLineage").active)

    def test_unregistered_technology_refused(self):
        with self.assertRaises(AdmissionDefect):
            self.reg.get("NoSuchTech")


if __name__ == "__main__":
    unittest.main()

    def test_build_new_exception_needs_evidenced_failures(self):
        """R-1: material failure asserted WITHOUT evidence must not satisfy the BUILD_NEW_EXCEPTION gate."""
        with self.assertRaises(AdmissionDefect) as c:
            assert_build_new_exception_allowed([
                CandidateDisposition("REUSE", materially_fails=True, evidence_ref=""),
                CandidateDisposition("WRAP", materially_fails=True, evidence_ref="e2"),
                CandidateDisposition("TRANSLATE", materially_fails=True, evidence_ref="e3"),
                CandidateDisposition("ADAPT", materially_fails=True, evidence_ref="e4"),
                CandidateDisposition("COMPOSE", materially_fails=True, evidence_ref="e5"),
                CandidateDisposition("BUILD_MINIMUM", materially_fails=True, evidence_ref="e6"),
                CandidateDisposition("BUILD_NEW_EXCEPTION")])
        self.assertIn("WITHOUT evidence", str(c.exception))
