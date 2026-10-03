"""Focused tests for named-capability ledger consumption (W1-EXT-005)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from capability.ledger import LedgerConsumptionReceipt, LedgerDefect, NamedRow  # noqa: E402


def row(**kw):
    base = dict(row_id="NC-01", family="capability", source_locator="PI-PKG-04#H1-06",
                source_disposition="WRAP", consumer="src/fabric", execution_disposition="CONSUMED_ACTIVE",
                readback_proof="test:test_binding.test_valid_binding_binds_and_advances_state")
    base.update(kw)
    return NamedRow(**base)


class TestLedger(unittest.TestCase):
    def test_reference_alone_is_not_consumption(self):
        """A locator with no readback proof must NOT satisfy CONSUMED_ACTIVE."""
        with self.assertRaises(LedgerDefect) as c:
            row(readback_proof="").consume()
        self.assertIn("readback proof", str(c.exception))

    def test_consumed_active_requires_consumer(self):
        with self.assertRaises(LedgerDefect):
            row(consumer="").consume()

    def test_not_active_requires_reason(self):
        with self.assertRaises(LedgerDefect):
            row(execution_disposition="NOT_ACTIVE_WITH_REASON", not_active_reason="").consume()

    def test_unknown_source_disposition_rejected(self):
        with self.assertRaises(LedgerDefect):
            row(source_disposition="MAYBE").consume()

    def test_silent_omission_refused(self):
        r = row(); r.execution_disposition = ""
        with self.assertRaises(LedgerDefect) as c:
            LedgerConsumptionReceipt().build([r])
        self.assertIn("silent omission", str(c.exception))

    def test_receipt_counts_and_digest(self):
        rec = LedgerConsumptionReceipt(workorder_id="WO-X", source_candidate_sha="a" * 40).build([
            row(row_id="NC-01"),
            row(row_id="NC-02", execution_disposition="NOT_ACTIVE_WITH_REASON",
                not_active_reason="technology deferred by source disposition"),
            row(row_id="WF-01", family="workflow", execution_disposition="DEFERRED"),
        ])
        self.assertEqual(rec.counts["total"], 3)
        self.assertEqual(rec.counts["consumed_active"], 1)
        self.assertEqual(rec.counts["unconsumed"], 0)
        self.assertTrue(rec.digest())

    def test_source_and_execution_dispositions_are_separate(self):
        d = row(source_disposition="REUSE_AS_REFERENCE", execution_disposition="DEFERRED").consume()
        self.assertEqual(d["source_disposition"], "REUSE_AS_REFERENCE")
        self.assertEqual(d["execution_disposition"], "DEFERRED")


if __name__ == "__main__":
    unittest.main()
