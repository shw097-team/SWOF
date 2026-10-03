"""Adversarial tests: each attack asserts its exact typed error / reason_code.

These are the tests that make the substrate falsifiable. Each one impersonates a specific
defect - a forged summary, a plausible-but-wrong hash, a maker checking its own work, a
checker that tries to repair the candidate, a tampered or truncated journal, a stale object
sold as direct-final, a moving branch tip sold as an immutable SHA, an oracle that cannot
fail - and asserts the exact rejection class, never a generic exception.
"""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from assurance.evidence import (  # noqa: E402
    EvidenceItem, EvidencePlan, EvidenceRejected, validate_item, validate_plan,
)
from assurance.journal import (  # noqa: E402
    DigestChainJournal, JournalEntry, JournalTamperDetected, from_lifecycle_rows,
)
from assurance.oracle import Oracle, OracleAmbiguous  # noqa: E402
from assurance.predicate import PredicateInvalid, validate  # noqa: E402
from assurance.sod import CheckerWriteRefused, ReadOnlyChecker  # noqa: E402

RAW = b"genuine-raw-proof"
SHA = hashlib.sha256(RAW).hexdigest()
OTHER_RAW = b"plausible-content-wrong-bytes"
OTHER_SHA = hashlib.sha256(OTHER_RAW).hexdigest()
ORACLE_ID = "ORACLE.SWOF.STD/1"


def plan(**overrides):
    base = {
        "plan_id": "PLAN-ADV",
        "subject_id": "SUBJ-ADV",
        "subject_sha": "immutable-subject-sha",
        "oracle_id": ORACLE_ID,
        "required": (("TEST_RUN", "DIRECT_FINAL_SUBJECT", "ENV-ADV"),),
        "checker_id": "checker-adv",
        "producer_id": "producer-adv",
    }
    base.update(overrides)
    return EvidencePlan(**base)


def item(**overrides):
    base = {
        "item_id": "adv-1",
        "kind": "TEST_RUN",
        "subject_id": "SUBJ-ADV",
        "subject_version": "v1",
        "sha256": SHA,
        "environment": "ENV-ADV",
        "action": "run",
        "checker_id": "checker-adv",
        "producer_id": "producer-adv",
        "raw_path": "adv/raw.bin",
        "linkage_mode": "DIRECT_FINAL_SUBJECT",
    }
    base.update(overrides)
    return EvidenceItem(**base)


def resolver(path):
    if path == "adv/raw.bin":
        return RAW
    if path == "adv/other.bin":
        return OTHER_RAW
    return None


class TestA1ForgedSummary(unittest.TestCase):
    def test_summary_boolean_without_raw_proof_is_refused(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(raw_path=None, is_summary_only=True), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "FORGED_SUMMARY")


class TestA2WrongSha(unittest.TestCase):
    def test_plausible_content_with_wrong_sha_is_refused(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(raw_path="adv/other.bin"), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "HASH_MISMATCH")


class TestA3MakerAsChecker(unittest.TestCase):
    def test_maker_as_checker_reason_code(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(checker_id="maker", producer_id="maker"), plan=plan(),
                          resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "CHECKER_EQUALS_PRODUCER")

    def test_maker_as_checker_sod_violation(self):
        from assurance.sod import SoDViolation, assert_separated
        with self.assertRaises(SoDViolation):
            assert_separated("maker", "maker")


class TestA4CheckerMutation(unittest.TestCase):
    def test_write_product_refused_and_candidate_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "predicate.py"
            candidate.write_bytes(b"the frozen candidate under check")
            before = candidate.read_bytes()
            checker = ReadOnlyChecker("checker-adv")
            with self.assertRaises(CheckerWriteRefused):
                checker.write_product(str(candidate), b"repaired by the checker")
            self.assertEqual(candidate.read_bytes(), before)


class TestA5EvidenceTamper(unittest.TestCase):
    def _journal(self):
        return from_lifecycle_rows([
            {"rowid": 1, "transition_id": "T1", "from_state": "A", "to_state": "B",
             "created_at": "t1"},
            {"rowid": 2, "transition_id": "T2", "from_state": "B", "to_state": "C",
             "created_at": "t2"},
        ])

    def test_payload_mutation_detected(self):
        journal = self._journal()
        entries = list(journal.entries)
        entries[0] = JournalEntry(seq=entries[0].seq, event_id=entries[0].event_id,
                                  payload={"rowid": 1, "to_state": "FORGED"},
                                  prev_digest=entries[0].prev_digest,
                                  entry_digest=entries[0].entry_digest)
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "ENTRY_DIGEST_MISMATCH")

    def test_deleted_entry_detected(self):
        journal = self._journal()
        journal.entries = [journal.entries[1]]
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "SEQ_GAP")

    def test_reordered_entries_are_prev_digest_mismatch_not_seq_gap(self):
        journal = self._journal()
        entries = list(journal.entries)
        entries[0], entries[1] = entries[1], entries[0]
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "PREV_DIGEST_MISMATCH")
        self.assertNotEqual(ctx.exception.reason_code, "SEQ_GAP")

    def test_deletion_and_reorder_collapse_to_distinct_reasons(self):
        deleted = self._journal()
        deleted.entries = [deleted.entries[1]]
        swapped = self._journal()
        entries = list(swapped.entries)
        entries[0], entries[1] = entries[1], entries[0]
        swapped.entries = entries
        deleted_reason = None
        swapped_reason = None
        with self.assertRaises(JournalTamperDetected) as ctx:
            deleted.verify()
        deleted_reason = ctx.exception.reason_code
        with self.assertRaises(JournalTamperDetected) as ctx:
            swapped.verify()
        swapped_reason = ctx.exception.reason_code
        self.assertEqual(deleted_reason, "SEQ_GAP")
        self.assertEqual(swapped_reason, "PREV_DIGEST_MISMATCH")
        self.assertNotEqual(deleted_reason, swapped_reason)

    def test_foreign_chain_splice_is_chain_id_mismatch(self):
        journal = self._journal()
        foreign = DigestChainJournal("FOREIGN-CHAIN")
        foreign.append(event_id="X", payload={"rowid": 9})
        entries = list(journal.entries)
        entries[0] = foreign.entries[0]
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "CHAIN_ID_MISMATCH")

    def test_header_tamper_is_header_mismatch(self):
        journal = self._journal()
        journal.header["final_digest"] = "0" * 64
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "HEADER_MISMATCH")

    def test_untouched_chain_is_intact(self):
        journal = self._journal()
        verdict = journal.verify()
        self.assertTrue(verdict["intact"])
        self.assertEqual(verdict["reason_code"], "INTACT")


class TestA6StaleDirectFinal(unittest.TestCase):
    def test_stale_pre_mutation_sold_as_direct_final(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(is_pre_mutation=True, linkage_mode="DIRECT_FINAL_SUBJECT"),
                          plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "DIRECT_FINAL_CLAIM_ON_PRE_MUTATION")

    def test_pre_mutation_transitive_lineage_is_allowed(self):
        transitive = plan(required=(("TEST_RUN", "TRANSITIVE_PRE_MUTATION_LINEAGE", "ENV-ADV"),))
        verdict = validate_item(item(is_pre_mutation=True,
                                     linkage_mode="TRANSITIVE_PRE_MUTATION_LINEAGE"),
                                plan=transitive, resolver=resolver)
        self.assertTrue(verdict["accepted"])


class TestA7BranchTipSubstitution(unittest.TestCase):
    def test_branch_tip_sold_as_immutable_sha(self):
        with self.assertRaises(EvidenceRejected) as ctx:
            validate_item(item(is_branch_tip=True), plan=plan(), resolver=resolver)
        self.assertEqual(ctx.exception.reason_code, "BRANCH_TIP_SUBSTITUTION")


class TestA8UnfalsifiableOracle(unittest.TestCase):
    def test_empty_predicate_is_refused(self):
        with self.assertRaises(PredicateInvalid) as ctx:
            validate({})
        self.assertEqual(ctx.exception.reason_code, "MISSING_PREDICATE_ID")

    def test_oracle_with_no_rules_is_ambiguous(self):
        with self.assertRaises(OracleAmbiguous) as ctx:
            Oracle("ORACLE.NOT.DEFINED/0").required_kinds()
        self.assertEqual(ctx.exception.reason_code, "ORACLE_UNDEFINED")

    def test_unrepresented_negative_fixture_does_not_pass(self):
        predicate = validate({
            "predicate_id": "P-ADV", "subject_id": "SUBJ-ADV", "subject_type": "DELIVERABLE",
            "required_evidence_kinds": frozenset({"TEST_RUN"}), "oracle_id": ORACLE_ID,
            "terminal_states": ("PASS", "FAIL"), "negative_fixtures": ("NEG-X",),
        })
        items = [{"item_id": "i", "kind": "TEST_RUN", "subject_id": "SUBJ-ADV",
                  "sha256": "a" * 64, "negative_fixtures": ()}]
        verdict = Oracle(ORACLE_ID).decide(predicate, items)
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.reason_code, "NEGATIVE_FIXTURE_UNREPRESENTED")

    def test_self_declared_negative_fixture_cannot_satisfy_the_law(self):
        predicate = validate({
            "predicate_id": "P-ADV", "subject_id": "SUBJ-ADV", "subject_type": "DELIVERABLE",
            "required_evidence_kinds": frozenset({"TEST_RUN"}), "oracle_id": ORACLE_ID,
            "terminal_states": ("PASS", "FAIL"), "negative_fixtures": ("NEG-X",),
        })
        lying = [{"item_id": "i", "kind": "TEST_RUN", "subject_id": "SUBJ-ADV",
                  "sha256": "a" * 64, "negative_fixtures": ("NEG-X",)}]
        verdict = Oracle(ORACLE_ID).decide(predicate, lying)
        self.assertFalse(verdict.passed)
        self.assertEqual(verdict.reason_code, "NEGATIVE_FIXTURE_UNREPRESENTED")

    def test_genuinely_represented_fixture_passes(self):
        predicate = validate({
            "predicate_id": "P-ADV", "subject_id": "SUBJ-ADV", "subject_type": "DELIVERABLE",
            "required_evidence_kinds": frozenset({"TEST_RUN"}), "oracle_id": ORACLE_ID,
            "terminal_states": ("PASS", "FAIL"), "negative_fixtures": ("NEG-X",),
        })
        proof = {"item_id": "proof", "kind": "NEGATIVE_FIXTURE_PROOF", "subject_id": "SUBJ-ADV",
                 "sha256": "b" * 64}
        item = {"item_id": "i", "kind": "TEST_RUN", "subject_id": "SUBJ-ADV",
                "sha256": "a" * 64}
        oracle = Oracle(ORACLE_ID, negative_fixture_manifest={"NEG-X": "NEGATIVE_FIXTURE_PROOF"})
        verdict = oracle.decide(predicate, [proof, item])
        self.assertTrue(verdict.passed)


class TestA9PlanPartialFailure(unittest.TestCase):
    def test_validate_plan_counts_partial_failures_separately(self):
        bad_direct = item(item_id="d", is_pre_mutation=True)
        bad_transitive = item(item_id="t",
                              linkage_mode="TRANSITIVE_PRE_MUTATION_LINEAGE", stale=True)
        verdict = validate_plan(plan(), [bad_direct, bad_transitive], resolver=resolver)
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["invalid_direct_link_count"], 1)
        self.assertEqual(verdict["invalid_transitive_link_count"], 1)

    def test_validate_plan_never_passes_on_empty(self):
        verdict = validate_plan(plan(), [], resolver=resolver)
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["checked"], 0)


class TestA10CoherentJournalRewrite(unittest.TestCase):
    def test_coherent_rewrite_surfaces_non_authoritative_header_and_manifest_catches_it(self):
        journal = from_lifecycle_rows([
            {"rowid": 1, "transition_id": "T1", "from_state": "A", "to_state": "B",
             "created_at": "t1"},
            {"rowid": 2, "transition_id": "T2", "from_state": "B", "to_state": "C",
             "created_at": "t2"},
            {"rowid": 3, "transition_id": "T3", "from_state": "C", "to_state": "D",
             "created_at": "t3"},
        ])
        manifest = journal.export_manifest()
        journal.entries = list(journal.entries[:-1])
        journal.header["entry_count"] = len(journal.entries)
        journal.header["final_digest"] = journal.entries[-1].entry_digest
        verdict = journal.verify()
        self.assertFalse(verdict["header_is_authoritative"])
        self.assertEqual(
            verdict["anchor_reason_code"],
            "COHERENT_HEADER_AND_ENTRY_REWRITE_UNDETECTABLE_WITHOUT_EXTERNAL_ANCHOR")
        anchored = journal.verify_against_manifest(manifest)
        self.assertFalse(anchored["intact"])
        self.assertTrue(anchored["header_is_authoritative"])


if __name__ == "__main__":
    unittest.main()
