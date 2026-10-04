"""Focused tests: dependency identity, pin/hash verification, licence and audit."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.supplychain import (  # noqa: E402
    ALLOWED_LICENSES, AUDIT_SCHEMA, DependencyIdentity, LicenseNotAllowed,
    SupplyChainIdentityMismatch, UnpinnedDependency, assert_license_allowed, assert_no_unpinned,
    audit, verify_pin,
)

HASH_A = "a" * 64
HASH_B = "b" * 64


def dep(**overrides):
    fields = {
        "name": "example-lib",
        "version": "1.2.3",
        "sha256": HASH_A,
        "license": "MIT",
        "security_metadata": {},
        "pinned": True,
    }
    fields.update(overrides)
    return DependencyIdentity(**fields)


class TestVerifyPin(unittest.TestCase):
    def test_matching_hash_passes(self):
        report = verify_pin(dep(), actual_sha256=HASH_A)
        self.assertTrue(report["verified"])
        self.assertEqual(report["name"], "example-lib")

    def test_hash_case_insensitive(self):
        verify_pin(dep(sha256=HASH_A.upper()), actual_sha256=HASH_A)

    def test_mismatched_hash_raises(self):
        with self.assertRaises(SupplyChainIdentityMismatch):
            verify_pin(dep(), actual_sha256=HASH_B)

    def test_missing_actual_hash_raises(self):
        with self.assertRaises(SupplyChainIdentityMismatch):
            verify_pin(dep(), actual_sha256=None)

    def test_missing_pinned_hash_raises(self):
        with self.assertRaises(SupplyChainIdentityMismatch):
            verify_pin(dep(sha256=None), actual_sha256=HASH_A)

    def test_unpinned_raises(self):
        with self.assertRaises(UnpinnedDependency):
            verify_pin(dep(pinned=False), actual_sha256=HASH_A)

    def test_unknown_dependency_raises(self):
        with self.assertRaises(UnpinnedDependency):
            verify_pin(object(), actual_sha256=HASH_A)

    def test_codes_are_stable(self):
        self.assertEqual(UnpinnedDependency.code, "ERR_UNPINNED_DEPENDENCY")
        self.assertEqual(SupplyChainIdentityMismatch.code, "ERR_SUPPLY_CHAIN_IDENTITY_MISMATCH")


class TestLicense(unittest.TestCase):
    def test_allowed_license_passes(self):
        assert_license_allowed(dep(license="Apache-2.0"), allowed_licenses=ALLOWED_LICENSES)

    def test_missing_license_raises(self):
        with self.assertRaises(LicenseNotAllowed):
            assert_license_allowed(dep(license=None), allowed_licenses=ALLOWED_LICENSES)

    def test_unknown_license_raises(self):
        with self.assertRaises(LicenseNotAllowed):
            assert_license_allowed(dep(license="WTFPL-9000"), allowed_licenses=ALLOWED_LICENSES)

    def test_malformed_policy_fails_closed(self):
        with self.assertRaises(LicenseNotAllowed):
            assert_license_allowed(dep(), allowed_licenses="MIT")

    def test_code_is_stable(self):
        self.assertEqual(LicenseNotAllowed.code, "ERR_LICENSE_NOT_ALLOWED")


class TestAssertNoUnpinned(unittest.TestCase):
    def test_all_pinned_passes(self):
        assert_no_unpinned([dep(), dep(name="other")])

    def test_empty_universe_passes(self):
        assert_no_unpinned([])

    def test_unpinned_in_list_raises(self):
        with self.assertRaises(UnpinnedDependency):
            assert_no_unpinned([dep(), dep(name="loose", pinned=False)])

    def test_none_universe_fails_closed(self):
        with self.assertRaises(UnpinnedDependency):
            assert_no_unpinned(None)


class TestAudit(unittest.TestCase):
    def test_empty_universe_is_clean(self):
        report = audit([])
        self.assertEqual(report["schema"], AUDIT_SCHEMA)
        self.assertTrue(report["clean"])
        self.assertEqual(report["failures"], [])

    def test_fully_admitted_dependency_is_clean(self):
        report = audit([dep()], actual_hashes={"example-lib": HASH_A})
        self.assertTrue(report["clean"])
        self.assertTrue(report["dependencies"][0]["admitted"])

    def test_hash_mismatch_marks_dirty(self):
        report = audit([dep()], actual_hashes={"example-lib": HASH_B})
        self.assertFalse(report["clean"])
        self.assertEqual(report["failures"][0]["code"], "ERR_SUPPLY_CHAIN_IDENTITY_MISMATCH")

    def test_unpinned_marks_dirty(self):
        report = audit([dep(pinned=False)], actual_hashes={"example-lib": HASH_A})
        self.assertFalse(report["clean"])
        self.assertEqual(report["failures"][0]["code"], "ERR_UNPINNED_DEPENDENCY")

    def test_bad_license_marks_dirty(self):
        report = audit([dep(license="NOPE")], actual_hashes={"example-lib": HASH_A})
        self.assertFalse(report["clean"])
        self.assertEqual(report["failures"][0]["code"], "ERR_LICENSE_NOT_ALLOWED")

    def test_failures_surface_per_item(self):
        report = audit([dep(), dep(name="loose", pinned=False)],
                       actual_hashes={"example-lib": HASH_A})
        self.assertEqual(len(report["failures"]), 1)
        self.assertEqual(report["schema"], "SWOF-SUPPLY-CHAIN-AUDIT/1")


if __name__ == "__main__":
    unittest.main()
