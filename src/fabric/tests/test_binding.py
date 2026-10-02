"""Focused tests for the binding algorithm and narrow waist (PI-PKG-04 §6.1/§6.2/§9.2/§9.4)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from fabric.binding import (  # noqa: E402
    ARCHITECTURAL_INVARIANTS, NARROW_WAIST, WAIST_LEGS, BindingRejected, ProviderProfile,
    ToolPermissionContract, assert_adapter_preserves_semantics,
    assert_no_provider_in_semantic_source, bind,
)
from fabric.capability_contract import AuthorityCapture, CapabilityContract, ContractInvalid  # noqa: E402
try:
    from tests.test_capability_contract import good_mapping  # noqa: E402
except ImportError:
    from test_capability_contract import good_mapping  # noqa: E402


def validated(**over):
    c = CapabilityContract.from_mapping(good_mapping(**over))
    c.advance("VALIDATED")
    return c


class TestNarrowWaist(unittest.TestCase):
    def test_narrow_waist_order_is_the_source_order(self):
        # PI-PKG-04 6.1: the waist is PlanIR -> Mission/TaskSpec/WorkOrder -> ECPDesignSchema
        # -> CapabilityContract -> HarnessABI (HarnessABI terminates the waist).
        self.assertEqual(NARROW_WAIST[-1], "HarnessABI")
        self.assertIn("CapabilityContract", NARROW_WAIST)
        self.assertIn(("ProviderBindingRef", "ProviderProfile"), WAIST_LEGS)

    def test_ten_architectural_invariants_present(self):
        self.assertEqual(len(ARCHITECTURAL_INVARIANTS), 10)
        self.assertIn("canonical_plan_ir_count = 1", ARCHITECTURAL_INVARIANTS[1])


class TestBinding(unittest.TestCase):
    def setUp(self):
        self.p = ProviderProfile(profile_id="P-A", qualified=True)
        self.perms = ToolPermissionContract(contract_id="TP-1", granted=["model.invoke"],
                                            denied=["fs.write"])
        self.kw = dict(binding_ref="BR-1", exit_path="exit.json", fallback_path="fb.json",
                       rollback_path="rb.json")

    def test_valid_binding_binds_and_advances_state(self):
        c = validated()
        ref = bind(c, self.p, self.perms, **self.kw)
        self.assertEqual(c.design_state, "SLOT_BOUND")
        self.assertEqual(c.provider_binding_ref, "BR-1")
        self.assertEqual(ref.capability_contract_digest, c.content_digest())
        self.assertEqual(ref.scoped_permissions, ["model.invoke"])

    def test_unqualified_provider_rejected(self):
        with self.assertRaises(BindingRejected):
            bind(validated(), ProviderProfile(profile_id="P-B", qualified=False), self.perms, **self.kw)

    def test_missing_exit_fallback_rollback_rejected(self):
        for k in ("exit_path", "fallback_path", "rollback_path"):
            kw = dict(self.kw); kw[k] = ""
            with self.assertRaises(BindingRejected):
                bind(validated(), self.p, self.perms, **kw)

    def test_denied_permission_wins(self):
        c = validated(requested_permissions=["fs.write"])
        with self.assertRaises(BindingRejected):
            bind(c, self.p, self.perms, **self.kw)

    def test_ungranted_permission_rejected(self):
        c = validated(requested_permissions=["net.egress"])
        with self.assertRaises(BindingRejected):
            bind(c, self.p, self.perms, **self.kw)

    def test_nonlocal_without_fallback_capability_rejected(self):
        c = validated(fallback_capability_ref=None)
        with self.assertRaises(ContractInvalid):
            bind(c, self.p, self.perms, nonlocal_execution=True, **self.kw)

    def test_binding_before_validation_rejected(self):
        c = CapabilityContract.from_mapping(good_mapping())  # still PROPOSED
        with self.assertRaises(BindingRejected):
            bind(c, self.p, self.perms, **self.kw)

    def test_p04_cr_001_adapter_may_not_change_semantic_meaning(self):
        before = good_mapping()
        after = dict(before, mission_ref="MISSION-CHANGED")
        with self.assertRaises(AuthorityCapture) as ctx:
            assert_adapter_preserves_semantics(before, after)
        self.assertEqual(ctx.exception.code, "TT-AUTHORITY-CAPTURE")
        assert_adapter_preserves_semantics(before, dict(before, capability_id="CAP-OTHER"))

    def test_p04_cr_001_provider_id_must_not_leak_into_semantic_source(self):
        with self.assertRaises(AuthorityCapture) as ctx:
            assert_no_provider_in_semantic_source({"mission_ref": "M-1", "provider_id": "P-A"})
        self.assertEqual(ctx.exception.code, "TT-AUTHORITY-CAPTURE")
        assert_no_provider_in_semantic_source({"mission_ref": "M-1"})


if __name__ == "__main__":
    unittest.main()

    def test_digest_is_stable_across_binding(self):
        """DEFECT-W1-002 regression: the subject key must not move when the contract is bound."""
        c = validated()
        before = c.content_digest()
        ref = bind(c, self.p, self.perms, **self.kw)
        self.assertEqual(c.content_digest(), before)
        self.assertEqual(ref.capability_contract_digest, before)
