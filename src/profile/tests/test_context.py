"""Focused tests for the W1 execution-context seam (PD-PKG-05)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from profile.context import (  # noqa: E402
    CapabilityProjectionProfile, ContextHandoffPacket, ExecutionContextProfile, PermissionEnvelope,
    ProfileDefect, QualificationHandoff, TeamTopology,
)


class TestTeamTopology(unittest.TestCase):
    def test_topology_validate(self):
        t = TeamTopology("T1", [{"id": "L1", "mode": "SERIAL"}]).validate()
        self.assertEqual(t.join_policy, "ALL_MUST_COMPLETE")

    def test_empty_topology_rejected(self):
        with self.assertRaises(ProfileDefect):
            TeamTopology("T1", []).validate()

    def test_bad_lane_mode_rejected(self):
        with self.assertRaises(ProfileDefect):
            TeamTopology("T1", [{"id": "L1", "mode": "UNBOUNDED"}]).validate()

    def test_design_topology_is_not_runtime_parallelism(self):
        t = TeamTopology("T1", [{"id": "L1", "mode": "BOUNDED_PARALLEL"}]).validate()
        self.assertFalse(t.runtime_parallelism_observed,
                         "a declared topology is never evidence that a runtime lane started")


class TestPermissionEnvelope(unittest.TestCase):
    def test_granted_permission_effective(self):
        e = PermissionEnvelope("E1", granted=["fs.read"], denied=["fs.write"])
        self.assertEqual(e.effective(["fs.read"]), ["fs.read"])

    def test_denied_wins(self):
        with self.assertRaises(ProfileDefect):
            PermissionEnvelope("E1", granted=["fs.read"], denied=["fs.write"]).effective(["fs.write"])

    def test_tool_presence_does_not_grant_rights(self):
        """PD-PKG-05: tool visibility / provider presence never increases rights."""
        with self.assertRaises(ProfileDefect) as c:
            PermissionEnvelope("E1", granted=[], denied=[]).effective(["net.egress"],
                                                                      tool_presence=["mcp:fetch"])
        self.assertIn("does not increase rights", str(c.exception))


class TestHandoffAndQualification(unittest.TestCase):
    def test_handoff_requires_checkpoint_and_recovery(self):
        with self.assertRaises(ProfileDefect):
            ContextHandoffPacket("H1", checkpoint_ref="", recovery_path="").validate()

    def test_handoff_valid(self):
        ContextHandoffPacket("H1", checkpoint_ref="CKPT-1", recovery_path="rb").validate()

    def test_projection_must_stay_provider_neutral(self):
        with self.assertRaises(ProfileDefect):
            CapabilityProjectionProfile("P1", "CC-1", provider_neutral=False).validate()

    def test_qualification_handoff_cannot_self_award_pass(self):
        with self.assertRaises(ProfileDefect):
            QualificationHandoff("Q1", "sha", checker_identity="").award_pass()

    def test_execution_context_profile_is_not_memory_truth(self):
        self.assertFalse(ExecutionContextProfile("X1").is_memory_truth)


if __name__ == "__main__":
    unittest.main()
