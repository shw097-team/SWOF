"""Focused tests for named-capability ledger consumption (W1-EXT-005 / R2-002).

The decisive test here is `test_opa_selected_for_predev_cannot_be_serialized_as_deferred`: the
external reviewer's counterexample (canonical `SELECTED_FOR_PREDEV` collapsed into the execution
label `DEFERRED`) must be UNREPRESENTABLE, not merely discouraged.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from capability.ledger import (  # noqa: E402
    ADMISSION_LADDER_DISPOSITIONS, EXEC_DISPOSITIONS, SOURCE_DISPOSITION_REGISTRY,
    LedgerConsumptionReceipt, LedgerDefect, NamedRow, SourceDispositionCoercion,
    SourceDispositionNotVerbatim, UnresolvedSourceDisposition,
)

OPA_TEXT = "**OPA / Rego — `OPA_POLICY_EVAL`.** `v1.20.2`, `SELECTED_FOR_PREDEV`, Apache-2.0"
OL_TEXT = "**OpenLineage — `OL_LINEAGE_ADAPTER`.** `1.53.0`, released 2026-09-01, `ADOPT_WITH_ADAPTER`"
CEDAR_TEXT = "**Cedar.** `REJECTED_FOR_PRIMARY_POLICY_SLOT`; no second primary evaluator."


def row(**kw):
    base = dict(row_id="NC-01", family="capability", source_locator="PI-PKG-05 r2 §19.1 L3597",
                source_disposition="ADOPT_WITH_ADAPTER", canonical_source_text=OL_TEXT,
                consumer="src/fabric", execution_disposition="CONSUMED_ACTIVE",
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

    def test_unknown_source_disposition_is_typed_registry_row(self):
        with self.assertRaises(UnresolvedSourceDisposition) as c:
            row(source_disposition="MAYBE", canonical_source_text="MAYBE").consume()
        self.assertEqual(c.exception.code, "TEMP_CLOSED_REGISTRY_ROW")

    def test_silent_omission_refused(self):
        r = row(); r.execution_disposition = ""
        with self.assertRaises(LedgerDefect) as c:
            LedgerConsumptionReceipt().build([r])
        self.assertIn("silent omission", str(c.exception))

    def test_receipt_counts_and_digest(self):
        rec = LedgerConsumptionReceipt(workorder_id="WO-X", source_candidate_sha="a" * 40).build([
            row(row_id="NC-01"),
            row(row_id="NC-02", source_locator="PI-PKG-05 r2 §19.1 L3603",
                source_disposition="REJECTED_FOR_PRIMARY_POLICY_SLOT", canonical_source_text=CEDAR_TEXT,
                consumer="", readback_proof="",
                execution_disposition="NOT_ACTIVE_WITH_REASON",
                not_active_reason="source rejected this slot for primary policy evaluation"),
            row(row_id="WF-01", family="workflow", source_locator="PI-PKG-05 r2 §19.1 L3595",
                source_disposition="SELECTED_FOR_PREDEV", canonical_source_text=OPA_TEXT,
                consumer="", readback_proof="", execution_disposition="DEFERRED"),
        ])
        self.assertEqual(rec.counts["total"], 3)
        self.assertEqual(rec.counts["consumed_active"], 1)
        self.assertEqual(rec.counts["unconsumed"], 0)
        self.assertEqual(rec.counts["distinct_source_dispositions"], 3)
        self.assertTrue(rec.digest())

    # -- R2-002 fidelity ---------------------------------------------------------------------
    def test_source_and_execution_dispositions_are_separate_axes(self):
        d = row(source_disposition="SELECTED_FOR_PREDEV", canonical_source_text=OPA_TEXT,
                consumer="", readback_proof="", execution_disposition="DEFERRED").consume()
        self.assertEqual(d["source_disposition"], "SELECTED_FOR_PREDEV")
        self.assertEqual(d["execution_disposition"], "DEFERRED")

    def test_opa_selected_for_predev_cannot_be_serialized_as_deferred(self):
        """The reviewer's exact counterexample must be refused, not merely discouraged."""
        with self.assertRaises(SourceDispositionCoercion) as c:
            row(source_disposition="DEFERRED", canonical_source_text=OPA_TEXT,
                consumer="", readback_proof="", execution_disposition="DEFERRED").consume()
        self.assertIn("EXECUTION-axis", str(c.exception))
        self.assertEqual(c.exception.code, "FAIL_NAMED_CARRY_FORWARD")

    def test_every_execution_label_is_refused_as_a_source_disposition(self):
        for label in EXEC_DISPOSITIONS:
            with self.subTest(label=label):
                with self.assertRaises(SourceDispositionCoercion):
                    row(source_disposition=label, canonical_source_text=OPA_TEXT).consume()

    def test_relabelled_field_with_real_source_quote_is_refused(self):
        """Claiming SELECTED_FOR_PREDEV while quoting the OpenLineage row must fail."""
        with self.assertRaises(SourceDispositionNotVerbatim):
            row(source_disposition="SELECTED_FOR_PREDEV", canonical_source_text=OL_TEXT,
                consumer="", readback_proof="", execution_disposition="DEFERRED").consume()

    def test_canonical_source_text_is_required(self):
        with self.assertRaises(SourceDispositionNotVerbatim):
            row(canonical_source_text="").consume()

    def test_temp_closed_prefixed_token_is_accepted(self):
        d = row(source_disposition="TEMP_CLOSED_SOMETHING",
                canonical_source_text="pin remains `TEMP_CLOSED_SOMETHING`",
                consumer="", readback_proof="", execution_disposition="DEFERRED").consume()
        self.assertEqual(d["source_disposition"], "TEMP_CLOSED_SOMETHING")

    def test_build_ladder_is_a_distinct_axis(self):
        """The Search-Before-Build ladder must not be usable as the source vocabulary."""
        self.assertNotIn("WRAP", SOURCE_DISPOSITION_REGISTRY)
        self.assertNotIn("BUILD_NEW_EXCEPTION", SOURCE_DISPOSITION_REGISTRY)
        self.assertIn("WRAP", ADMISSION_LADDER_DISPOSITIONS)
        for tok in SOURCE_DISPOSITION_REGISTRY:
            self.assertNotIn(tok, EXEC_DISPOSITIONS)

    def test_registry_tokens_carry_a_locator(self):
        for tok, loc in SOURCE_DISPOSITION_REGISTRY.items():
            with self.subTest(tok=tok):
                self.assertIn("PI-PKG-05", loc)

    # -- disposition evidence tiers ------------------------------------------------------------
    def test_assigned_terminal_set_row_is_accepted_with_obligation_quote(self):
        """An internal construction row may use a terminal-set token, and must say it is assigned."""
        d = row(source_locator="PI-PKG-04 §6.1 narrow waist",
                source_disposition="CONSTRUCTION_ONLY",
                canonical_source_text="the W1 narrow waist must be constructed behind the contracts",
                disposition_evidence="ASSIGNED_TERMINAL_SET").consume()
        self.assertEqual(d["source_disposition"], "CONSTRUCTION_ONLY")
        self.assertEqual(d["disposition_evidence"], "ASSIGNED_TERMINAL_SET")

    def test_assigned_row_may_not_use_a_non_terminal_token(self):
        with self.assertRaises(UnresolvedSourceDisposition):
            row(source_disposition="SELECTED_FOR_PREDEV", canonical_source_text="internal seam",
                disposition_evidence="ASSIGNED_TERMINAL_SET").consume()

    def test_assigned_row_may_still_not_use_an_execution_label(self):
        with self.assertRaises(SourceDispositionCoercion):
            row(source_disposition="DEFERRED", canonical_source_text="internal seam",
                disposition_evidence="ASSIGNED_TERMINAL_SET").consume()

    def test_unknown_disposition_evidence_kind_is_refused(self):
        with self.assertRaises(LedgerDefect):
            row(disposition_evidence="PROBABLY").consume()


class TestReceiptSchema(unittest.TestCase):
    """The schema must be load-bearing: it has to accept a faithful receipt and reject coercion."""

    SCHEMA = ROOT / "schemas" / "capability" / "named_consumption.schema.json"

    def _validate(self, instance):
        import jsonschema
        jsonschema.validate(instance, json.loads(self.SCHEMA.read_text(encoding="utf-8")))

    def test_real_receipt_conforms(self):
        inst = json.loads((Path(__file__).resolve().parents[3] / "schemas" / "capability"
                           / "_conformance_sample.json").read_text(encoding="utf-8"))
        self._validate(inst)

    def test_schema_rejects_execution_label_as_source_disposition(self):
        import jsonschema
        inst = {
            "schema": "SWOF-NAMED-CAPABILITY-CONSUMPTION/1", "workorder_id": "W", "source_candidate_sha": "a" * 40,
            "rows": [{"row_id": "R", "family": "capability", "source_locator": "L",
                      "source_disposition": "DEFERRED",
                      "canonical_source_text": "SELECTED_FOR_PREDEV",
                      "disposition_evidence": "SOURCE_VERBATIM",
                      "execution_disposition": "DEFERRED"}],
            "counts": {"total": 1, "unconsumed": 0},
        }
        with self.assertRaises(jsonschema.ValidationError):
            self._validate(inst)

    def test_schema_rejects_assigned_row_using_a_non_terminal_token(self):
        import jsonschema
        inst = {
            "schema": "SWOF-NAMED-CAPABILITY-CONSUMPTION/1", "workorder_id": "W", "source_candidate_sha": "a" * 40,
            "rows": [{"row_id": "R", "family": "capability", "source_locator": "L",
                      "source_disposition": "SELECTED_FOR_PREDEV",
                      "canonical_source_text": "internal seam",
                      "disposition_evidence": "ASSIGNED_TERMINAL_SET",
                      "execution_disposition": "DEFERRED"}],
            "counts": {"total": 1, "unconsumed": 0},
        }
        with self.assertRaises(jsonschema.ValidationError):
            self._validate(inst)

    def test_schema_rejects_nonzero_unconsumed(self):
        import jsonschema
        inst = {
            "schema": "SWOF-NAMED-CAPABILITY-CONSUMPTION/1", "workorder_id": "W", "source_candidate_sha": "a" * 40,
            "rows": [{"row_id": "R", "family": "capability", "source_locator": "L",
                      "source_disposition": "CONSTRUCTION_ONLY",
                      "canonical_source_text": "must be constructed",
                      "disposition_evidence": "ASSIGNED_TERMINAL_SET",
                      "execution_disposition": "DEFERRED"}],
            "counts": {"total": 1, "unconsumed": 3},
        }
        with self.assertRaises(jsonschema.ValidationError):
            self._validate(inst)


if __name__ == "__main__":
    unittest.main()
