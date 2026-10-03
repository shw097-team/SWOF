"""Tests: digest-chain detection of post-export tampering, manifests, and the threat model."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from assurance.journal import (  # noqa: E402
    DigestChainJournal, JournalEntry, JournalTamperDetected, from_lifecycle_rows,
    threat_assessment,
)

ROWS = [
    {"rowid": 1, "transition_id": "T1", "from_state": "DRAFT", "to_state": "REVIEW",
     "created_at": "2026-01-01T00:00:00Z"},
    {"rowid": 2, "transition_id": "T2", "from_state": "REVIEW", "to_state": "ACCEPTED",
     "created_at": "2026-01-02T00:00:00Z"},
    {"rowid": 3, "transition_id": "T3", "from_state": "ACCEPTED", "to_state": "SEALED",
     "created_at": "2026-01-03T00:00:00Z"},
]


def built():
    return from_lifecycle_rows(ROWS)


class TestIntact(unittest.TestCase):
    def test_intact_chain_verifies(self):
        journal = built()
        verdict = journal.verify()
        self.assertTrue(verdict["intact"])
        self.assertEqual(verdict["checked"], 3)
        self.assertIsNone(verdict["first_broken_seq"])
        self.assertEqual(verdict["reason_code"], "INTACT")

    def test_entries_are_chained(self):
        journal = built()
        self.assertEqual(journal.entries[0].prev_digest, journal.genesis_digest)
        self.assertEqual(journal.entries[1].prev_digest, journal.entries[0].entry_digest)
        self.assertIsInstance(journal.entries[0], JournalEntry)

    def test_append_is_deterministic(self):
        first = built()
        second = built()
        self.assertEqual([e.entry_digest for e in first.entries],
                         [e.entry_digest for e in second.entries])

    def test_from_lifecycle_rows_writes_nothing_back(self):
        rows = [dict(row) for row in ROWS]
        from_lifecycle_rows(rows)
        self.assertEqual(rows, ROWS)


class TestTamperDetection(unittest.TestCase):
    def test_payload_mutation_is_entry_digest_mismatch(self):
        journal = built()
        entries = list(journal.entries)
        entries[1] = JournalEntry(seq=entries[1].seq, event_id=entries[1].event_id,
                                  payload={"rowid": 2, "to_state": "FORGED"},
                                  prev_digest=entries[1].prev_digest,
                                  entry_digest=entries[1].entry_digest)
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "ENTRY_DIGEST_MISMATCH")
        self.assertEqual(JournalTamperDetected.code, "ERR_JOURNAL_TAMPER_DETECTED")

    def test_deleted_entry_is_seq_gap(self):
        journal = built()
        journal.entries = [journal.entries[0], journal.entries[2]]
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "SEQ_GAP")

    def test_reordered_entries_is_prev_digest_mismatch(self):
        journal = built()
        entries = list(journal.entries)
        entries[0], entries[1] = entries[1], entries[0]
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "PREV_DIGEST_MISMATCH")

    def test_swapped_middle_entries_is_prev_digest_mismatch(self):
        journal = built()
        journal.append(event_id="T4", payload={"rowid": 4})
        entries = list(journal.entries)
        entries[1], entries[2] = entries[2], entries[1]
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "PREV_DIGEST_MISMATCH")

    def test_foreign_chain_splice_is_chain_id_mismatch(self):
        journal = built()
        foreign = DigestChainJournal("SOME-OTHER-CHAIN")
        foreign.append(event_id="X", payload={"rowid": 99})
        entries = list(journal.entries)
        entries[0] = foreign.entries[0]
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "CHAIN_ID_MISMATCH")

    def test_header_tampering_is_header_mismatch(self):
        journal = built()
        journal.header["final_digest"] = "0" * 64
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "HEADER_MISMATCH")

    def test_header_count_inflation_is_header_mismatch(self):
        journal = built()
        journal.append(event_id="T4", payload={"rowid": 4})
        journal.header["entry_count"] = 2
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "HEADER_MISMATCH")

    def test_truncated_tail_is_seq_gap(self):
        journal = built()
        journal.entries = journal.entries[:2]
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "SEQ_GAP")


class TestDistinctReasons(unittest.TestCase):
    def _reason(self, entries):
        journal = built()
        journal.entries = entries
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        return ctx.exception.reason_code

    def test_untouched_chain_is_intact(self):
        journal = built()
        self.assertTrue(journal.verify()["intact"])
        self.assertEqual(journal.verify()["reason_code"], "INTACT")

    def test_payload_mutation_reason(self):
        journal = built()
        entries = list(journal.entries)
        entries[1] = JournalEntry(seq=entries[1].seq, event_id=entries[1].event_id,
                                  payload={"rowid": 2, "to_state": "FORGED"},
                                  prev_digest=entries[1].prev_digest,
                                  entry_digest=entries[1].entry_digest)
        self.assertEqual(self._reason(entries), "ENTRY_DIGEST_MISMATCH")

    def test_deletion_reason(self):
        journal = built()
        entries = [journal.entries[0], journal.entries[2]]
        self.assertEqual(self._reason(entries), "SEQ_GAP")

    def test_truncation_reason(self):
        journal = built()
        self.assertEqual(self._reason(journal.entries[:2]), "SEQ_GAP")

    def test_reorder_reason(self):
        journal = built()
        entries = list(journal.entries)
        entries[0], entries[1] = entries[1], entries[0]
        self.assertEqual(self._reason(entries), "PREV_DIGEST_MISMATCH")

    def test_foreign_chain_reason(self):
        journal = built()
        foreign = DigestChainJournal("SOME-OTHER-CHAIN")
        foreign.append(event_id="X", payload={"rowid": 99})
        entries = list(journal.entries)
        entries[0] = foreign.entries[0]
        self.assertEqual(self._reason(entries), "CHAIN_ID_MISMATCH")

    def test_header_tamper_reason(self):
        journal = built()
        journal.header["final_digest"] = "0" * 64
        with self.assertRaises(JournalTamperDetected) as ctx:
            journal.verify()
        self.assertEqual(ctx.exception.reason_code, "HEADER_MISMATCH")

    def test_deletion_and_reorder_reasons_are_distinct(self):
        journal = built()
        deleted = self._reason([journal.entries[0], journal.entries[2]])
        swapped = self._reason([journal.entries[1], journal.entries[0], journal.entries[2]])
        self.assertEqual(deleted, "SEQ_GAP")
        self.assertEqual(swapped, "PREV_DIGEST_MISMATCH")
        self.assertNotEqual(deleted, swapped)


class TestManifest(unittest.TestCase):
    def test_manifest_contents(self):
        journal = built()
        manifest = journal.export_manifest()
        self.assertEqual(manifest["chain_id"], "HGK-LIFECYCLE-EXPORT")
        self.assertEqual(manifest["entry_count"], 3)
        self.assertEqual(len(manifest["entry_digests"]), 3)
        self.assertEqual(manifest["final_digest"], journal.entries[-1].entry_digest)

    def test_manifest_verifies_against_re_export(self):
        journal = built()
        verdict = DigestChainJournal.verify_manifest(journal.export_manifest(), journal.entries)
        self.assertTrue(verdict["intact"])
        self.assertEqual(verdict["checked"], 3)

    def test_manifest_detects_changed_entry_list(self):
        journal = built()
        manifest = journal.export_manifest()
        altered = [journal.entries[0], journal.entries[2]]
        verdict = DigestChainJournal.verify_manifest(manifest, altered)
        self.assertFalse(verdict["intact"])
        self.assertNotEqual(verdict["reason_code"], "INTACT")

    def test_manifest_detects_mutated_payload(self):
        journal = built()
        manifest = journal.export_manifest()
        entries = list(journal.entries)
        entries[1] = JournalEntry(seq=entries[1].seq, event_id=entries[1].event_id,
                                  payload={"rowid": 2, "to_state": "FORGED"},
                                  prev_digest=entries[1].prev_digest,
                                  entry_digest=entries[1].entry_digest)
        verdict = DigestChainJournal.verify_manifest(manifest, entries)
        self.assertFalse(verdict["intact"])
        self.assertEqual(verdict["reason_code"], "ENTRY_DIGEST_MISMATCH")


class TestThreatAssessment(unittest.TestCase):
    def test_assessment_states_detection_only(self):
        assessment = threat_assessment()
        self.assertEqual(assessment["schema"], "SWOF-W2-JOURNAL-INTEGRITY-ASSESSMENT/1")
        self.assertTrue(assessment["implemented"])
        self.assertEqual(assessment["protection_class"], "DETECTION_ONLY_NO_KEY_MANAGEMENT")
        self.assertFalse(assessment["db_level_enforcement_claimed"])
        self.assertFalse(assessment["writes_to_hgk"])
        self.assertTrue(assessment["justified"])

    def test_assessment_states_non_claims_explicitly(self):
        text = " ".join(threat_assessment()["does_not_give"]).lower()
        self.assertIn("tamper-proof", text)
        self.assertIn("not a cryptographic signature", text)
        self.assertIn("read-only", text)
        self.assertIn("w1 subject", text)


class TestUnauthenticatedHeader(unittest.TestCase):
    def _rewritten(self):
        journal = built()
        manifest = journal.export_manifest()
        journal.entries = list(journal.entries[:-1])
        journal.header["entry_count"] = len(journal.entries)
        journal.header["final_digest"] = journal.entries[-1].entry_digest
        return journal, manifest

    def test_coherent_rewrite_is_not_an_authoritative_intact(self):
        journal, _ = self._rewritten()
        verdict = journal.verify()
        self.assertTrue(verdict["intact"])
        self.assertFalse(verdict["header_is_authoritative"])
        self.assertEqual(
            verdict["anchor_reason_code"],
            "COHERENT_HEADER_AND_ENTRY_REWRITE_UNDETECTABLE_WITHOUT_EXTERNAL_ANCHOR")

    def test_verify_against_manifest_catches_the_truncation(self):
        journal, manifest = self._rewritten()
        verdict = journal.verify_against_manifest(manifest)
        self.assertFalse(verdict["intact"])
        self.assertEqual(verdict["reason_code"], "ENTRY_DIGEST_MISMATCH")
        self.assertTrue(verdict["header_is_authoritative"])

    def test_unmodified_chain_against_manifest_is_authoritative_intact(self):
        journal = built()
        verdict = journal.verify_against_manifest(journal.export_manifest())
        self.assertTrue(verdict["intact"])
        self.assertTrue(verdict["header_is_authoritative"])


if __name__ == "__main__":
    unittest.main()
