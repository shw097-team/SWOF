"""Focused tests for CapabilityContract (PI-PKG-04 §9.1)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from fabric.capability_contract import (  # noqa: E402
    ContractInvalid, UnknownNormativeField, CapabilityContract, SEMANTIC_WRITER,
)


def good_mapping(**over):
    m = {
        "contract_id": "CC-001", "semantic_subject_ref": "PI-PKG-04#H1-06/6.1",
        "mission_ref": "MISSION-001", "taskspec_ref": "TS-WO-X", "ecp_design_ref": "ECP-WO-X",
        "capability_id": "CAP-LLM-GENERATE", "capability_version": "1.0.0",
        "input_schema_ref": "schemas/fabric/in.schema.json",
        "output_schema_ref": "schemas/fabric/out.schema.json",
        "error_schema_ref": "schemas/fabric/err.schema.json",
        "required_effect_class": "NONE_OBSERVATIONAL",
        "requested_permissions": ["model.invoke"], "denied_permissions": ["fs.write"],
        "budget": {"time_ms": 30000, "token_or_compute": 100000, "money_ceiling": 0.0, "retry_budget": 2},
        "timeout_policy": {"mode": "hard"}, "retry_policy": {"mode": "bounded"},
        "idempotency_class": "IDEMPOTENT_READ",
        "evidence_contract_ref": "EV-CONTRACT-001", "compatibility_range": ">=1.0.0 <2.0.0",
        "fallback_capability_ref": "CAP-LOCAL-FALLBACK",
    }
    m.update(over)
    return m


class TestCapabilityContract(unittest.TestCase):
    def test_valid_contract_parses_and_validates(self):
        c = CapabilityContract.from_mapping(good_mapping())
        self.assertEqual(c.design_state, "PROPOSED")
        self.assertEqual(c.semantic_writer, SEMANTIC_WRITER)
        self.assertIsNone(c.provider_binding_ref, "provider binding must be late-bound/empty at design time")

    def test_missing_required_field_is_contract_invalid(self):
        m = good_mapping()
        del m["capability_id"]
        with self.assertRaises(ContractInvalid) as ctx:
            CapabilityContract.from_mapping(m)
        self.assertIn("capability_id", str(ctx.exception))

    def test_unknown_field_rejected_by_design_parser(self):
        with self.assertRaises(UnknownNormativeField):
            CapabilityContract.from_mapping(good_mapping(some_vendor_flag=True))

    def test_namespaced_extension_allowed_only_for_migration(self):
        c = CapabilityContract.from_mapping(good_mapping(**{"x-vendor": {"a": 1}}), parser="migration")
        self.assertEqual(c.extensions, {"x-vendor": {"a": 1}})

    def test_provider_side_semantic_write_is_authority_capture(self):
        with self.assertRaises(Exception) as ctx:
            CapabilityContract.from_mapping(good_mapping(semantic_writer="PROVIDER")).validate()
        self.assertEqual(getattr(ctx.exception, "code", None), "TT-AUTHORITY-CAPTURE")

    def test_digest_is_stable_and_canonical(self):
        a = CapabilityContract.from_mapping(good_mapping())
        b = CapabilityContract.from_mapping(dict(reversed(list(good_mapping().items()))))
        self.assertEqual(a.content_digest(), b.content_digest(), "key order must not change the digest")

    def test_digest_changes_with_semantics(self):
        a = CapabilityContract.from_mapping(good_mapping())
        b = CapabilityContract.from_mapping(good_mapping(capability_id="CAP-OTHER"))
        self.assertNotEqual(a.content_digest(), b.content_digest())

    def test_illegal_state_transition_rejected(self):
        c = CapabilityContract.from_mapping(good_mapping())
        with self.assertRaises(ContractInvalid):
            c.advance("SLOT_BOUND")

    def test_state_machine_advances_one_step(self):
        c = CapabilityContract.from_mapping(good_mapping())
        self.assertEqual(c.advance("VALIDATED").design_state, "VALIDATED")


if __name__ == "__main__":
    unittest.main()
