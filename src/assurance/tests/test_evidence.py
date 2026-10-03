"""Tests: every evidence rejection class, raw-proof binding, and plan counters."""
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from assurance.evidence import (  # noqa: E402
    LINKAGE_MODES, REASONS, EvidenceItem, EvidencePlan, EvidenceRejected, invalidate,
    validate_item, validate_plan,
)

RAW = b"raw-proof-bytes"
SHA = hashlib.sha256(RAW).hexdigest()
OTHER_RAW = b"plausible-but-different"
OTHER_SHA = hashlib.sha256(OTHER_RAW).hexdigest()


def plan(**overrides):
    base = {
        "plan_id": "PLAN-1",
        "subject_id": "SUBJ-1",
        "subject_sha": "subject-sha-1",
        "oracle_id": "ORACLE.SWOF.STD/1",
        "required": (("TEST_RUN", "DIRECT_FINAL_SUBJECT", "ENV-1"),),
        "checker_id": "checker-1",
        "producer_id": "producer-1",
    }
    base.update(overrides)
    return EvidencePlan(**base)


def item(**overrides):
    base = {
        "item_id": "item-1",
        "kind": "TEST_RUN",
        "subject_id": "SUBJ-1",
        "subject_version": "v1",
        "sha256": SHA,
        "environment": "ENV-1",
        "action": "run-tests",
        "checker_id": "checker-1",
        "producer_id": "producer-1",
        "raw_path": "evidence/item-1.bin",
        "linkage_mode": "DIRECT_FINAL_SUBJECT",
    }
    base.update(overrides)
    return EvidenceItem(**base)


def resolver(path):
    if path == "evidence/item-1.bin":
        return RAW
    if path == "evidence/other.bin":
        return OTHER_RAW
    return None


class TestAccepted(unittest.TestCase):
    def test_valid_item_is_accepted(self):
        verdict = validate_item(item(), plan=plan(), resolver=resolver)
        self.assertTrue(verdict["accepted"])
        self.assertEqual(verdict["reason_code"], "ACCEPTED")


class TestRejectionClasses(unittest.TestCase):
    def test_forged_summary_without_raw_proof(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(raw_path=None, is_summary_only=True), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "FORGED_SUMMARY")

    def test_wrong_sha_plausible_content(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(raw_path="evidence/other.bin"), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "HASH_MISMATCH")

    def test_missing_raw_proof(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(raw_path=None), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "RAW_PROOF_MISSING")

    def test_wrong_subject(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(subject_id="SUBJ-OTHER"), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "WRONG_SUBJECT")

    def test_declared_subject_mismatch(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(declared_subject_id="SUBJ-OTHER"), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "WRONG_SUBJECT")

    def test_pre_mutation_claimed_direct_final(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(is_pre_mutation=True), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "DIRECT_FINAL_CLAIM_ON_PRE_MUTATION")

    def test_branch_tip_substitution(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(is_branch_tip=True), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "BRANCH_TIP_SUBSTITUTION")

    def test_stale(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(stale=True), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "STALE")

    def test_foreign_environment(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(environment="ENV-OTHER"), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "FOREIGN")

    def test_checker_equals_producer(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(checker_id="maker-1", producer_id="maker-1"), plan=plan(),
                          resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "CHECKER_EQUALS_PRODUCER")

    def test_self_referential(self):
        self_ref = dict(plan().__dict__)
        self_ref["pack_path"] = "packs/PLAN-1"
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(raw_path="packs/PLAN-1/evidence/item-1.bin"),
                          plan=self_ref, resolver=lambda p: RAW)
        self.assertEqual(ctx.exception.reason_code, "SELF_REFERENTIAL")

    def test_every_reason_is_reachable(self):
        reached = set()
        cases = [
            (item(raw_path=None, is_summary_only=True), "FORGED_SUMMARY"),
            (item(raw_path="evidence/other.bin"), "HASH_MISMATCH"),
            (item(subject_id="X"), "WRONG_SUBJECT"),
            (item(is_pre_mutation=True), "DIRECT_FINAL_CLAIM_ON_PRE_MUTATION"),
            (item(is_branch_tip=True), "BRANCH_TIP_SUBSTITUTION"),
            (item(stale=True), "STALE"),
            (item(environment="OTHER"), "FOREIGN"),
            (item(checker_id="m", producer_id="m"), "CHECKER_EQUALS_PRODUCER"),
        ]
        for candidate, expected in cases:
            try:
                validate_item(candidate, plan=plan(), resolver=resolver)
            except EvidenceRejected as exc:
                self.assertEqual(exc.reason_code, expected)
                reached.add(exc.reason_code)
        self.assertTrue(reached.issubset(set(REASONS)))
        self.assertIn("HASH_MISMATCH", reached)


class TestPlanVerdict(unittest.TestCase):
    def test_valid_plan_passes(self):
        verdict = validate_plan(plan(), [item()], resolver=resolver)
        self.assertEqual(verdict["schema"], "SWOF-EVIDENCE-PLAN-VERDICT/1")
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["checked"], 1)
        self.assertEqual(verdict["required_present"], 1)

    def test_empty_item_list_never_passes(self):
        verdict = validate_plan(plan(), [], resolver=resolver)
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["checked"], 0)

    def test_linkage_counters_are_separate(self):
        verdict = validate_plan(plan(), [item()], resolver=resolver)
        self.assertEqual(set(verdict["linkage_modes"]), set(LINKAGE_MODES))

    def test_partial_failure_counters_separate(self):
        bad_direct = item(item_id="d", is_pre_mutation=True)
        bad_transitive = item(item_id="t",
                              linkage_mode="TRANSITIVE_PRE_MUTATION_LINEAGE", stale=True)
        verdict = validate_plan(plan(), [bad_direct, bad_transitive], resolver=resolver)
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["invalid_direct_link_count"], 1)
        self.assertEqual(verdict["invalid_transitive_link_count"], 1)
        self.assertEqual(len(verdict["rejected"]), 2)

    def test_required_missing_fails(self):
        verdict = validate_plan(plan(), [item(kind="OTHER")], resolver=resolver)
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["required_present"], 0)


class TestInvalidate(unittest.TestCase):
    def test_identity_change_returns_cone(self):
        gates = [
            {"gate_id": "G-1", "subject_sha": "old", "oracle_id": "ORACLE.SWOF.STD/1"},
            {"gate_id": "G-2", "subject_sha": "new", "oracle_id": "ORACLE.SWOF.STD/1"},
        ]
        affected = invalidate(plan(), changed_identity={"subject_sha": "new"}, gates=gates)
        ids = [entry["gate_id"] for entry in affected]
        self.assertEqual(ids, ["G-1"])

    def test_oracle_change_invalidates_the_superseded_gate_only(self):
        gates = [
            {"gate_id": "G-OLD", "oracle_id": "ORACLE.SWOF.STD/1",
             "environment": "ENV-OLD"},
            {"gate_id": "G-NEW", "oracle_id": "ORACLE.SWOF.STD/2",
             "environment": "ENV-NEW"},
        ]
        affected = invalidate(
            plan(), changed_identity={"oracle_id": "ORACLE.SWOF.STD/2",
                                      "environment": "ENV-NEW"}, gates=gates)
        self.assertEqual([entry["gate_id"] for entry in affected], ["G-OLD"])
        self.assertEqual(affected[0]["reason_codes"],
                         ["ORACLE_ID_CHANGED", "ENVIRONMENT_CHANGED"])

    def test_unrelated_axis_change_invalidates_nothing(self):
        gates = [
            {"gate_id": "G-1", "subject_sha": "sha-1", "oracle_id": "ORACLE.SWOF.STD/1",
             "environment": "ENV-1"},
            {"gate_id": "G-2", "subject_sha": "sha-2", "oracle_id": "ORACLE.SWOF.STD/2",
             "environment": "ENV-2"},
        ]
        affected = invalidate(plan(), changed_identity={"oracle_id": "ORACLE.SWOF.STD/1"},
                              gates=gates)
        self.assertEqual([entry["gate_id"] for entry in affected], ["G-2"])
        self.assertEqual(affected[0]["reason_codes"], ["ORACLE_ID_CHANGED"])

    def test_gate_without_a_binding_is_not_invalidated_by_that_axis(self):
        gates = [{"gate_id": "G-UNBOUND"}]
        affected = invalidate(plan(), changed_identity={"environment": "ENV-2"}, gates=gates)
        self.assertEqual(affected, [])

    def test_unchanged_identity_invalidates_nothing(self):
        gates = [
            {"gate_id": "G-1", "subject_sha": "sha-1", "oracle_id": "ORACLE.SWOF.STD/1",
             "environment": "ENV-1"},
        ]
        affected = invalidate(plan(), changed_identity={"subject_sha": "sha-1",
                                                        "oracle_id": "ORACLE.SWOF.STD/1",
                                                        "environment": "ENV-1"}, gates=gates)
        self.assertEqual(affected, [])

    def test_no_change_no_cone(self):
        gates = [{"gate_id": "G-1", "subject_sha": "x"}]
        self.assertEqual(invalidate(plan(), changed_identity={}, gates=gates), [])


class TestSecurityAxisDiscrimination(unittest.TestCase):
    def test_superseded_security_binding_is_invalidated(self):
        gates = [{"gate_id": "G-OLD", "security_config": "SEC-OLD"}]
        affected = invalidate(plan(), changed_identity={"security_config": "SEC-NEW"}, gates=gates)
        self.assertEqual([entry["gate_id"] for entry in affected], ["G-OLD"])
        self.assertEqual(affected[0]["reason_codes"], ["SECURITY_CONFIG_CHANGED"])

    def test_current_security_binding_is_untouched(self):
        gates = [{"gate_id": "G-NEW", "security_config": "SEC-NEW"}]
        affected = invalidate(plan(), changed_identity={"security_config": "SEC-NEW"}, gates=gates)
        self.assertEqual(affected, [])

    def test_unbound_gate_is_untouched_by_the_security_axis(self):
        gates = [{"gate_id": "G-UNBOUND"}]
        affected = invalidate(plan(), changed_identity={"security_config": "SEC-NEW"}, gates=gates)
        self.assertEqual(affected, [])


if __name__ == "__main__":
    unittest.main()
