"""Focused tests: secret/PII classification, redaction and the evidence no-secret gate."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.classification import (  # noqa: E402
    CLASSES, DETECTORS, SecretExfiltrationBlocked, assert_no_secret, classify, classify_many,
    detector_selftest, redact, sanitize_evidence,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class TestClassify(unittest.TestCase):
    def test_public_text(self):
        self.assertEqual(classify("the release notes are in the wiki"), "PUBLIC")

    def test_email_is_pii(self):
        self.assertEqual(classify("contact alice.chen@example.com"), "PII")

    def test_aws_key_is_secret(self):
        self.assertEqual(classify("key %s here" % AWS_KEY), "SECRET")

    def test_secret_outranks_pii(self):
        self.assertEqual(classify("a@b.co and %s" % AWS_KEY), "SECRET")

    def test_private_key_block_is_secret(self):
        self.assertEqual(classify("-----BEGIN RSA PRIVATE KEY-----"), "SECRET")

    def test_card_like_number_is_pii(self):
        self.assertEqual(classify("4111 1111 1111 1111"), "PII")

    def test_taiwan_id_is_pii(self):
        self.assertEqual(classify("A123456789"), "PII")

    def test_non_string_is_secret_fail_closed(self):
        self.assertEqual(classify(None), "SECRET")

    def test_class_order_is_monotonic(self):
        self.assertEqual(CLASSES, ("PUBLIC", "INTERNAL", "PII", "SECRET"))


class TestRedact(unittest.TestCase):
    def test_email_is_redacted(self):
        self.assertEqual(redact("mail a@b.co now"), "mail [REDACTED:PII] now")

    def test_secret_is_redacted(self):
        self.assertEqual(redact("token %s" % AWS_KEY), "token [REDACTED:SECRET]")

    def test_custom_replacement_is_used(self):
        self.assertEqual(redact("a@b.co", replacement="***"), "***")

    def test_benign_text_is_byte_identical(self):
        text = "nothing sensitive here at all"
        self.assertEqual(redact(text), text)

    def test_unicode_free_benign_number_is_not_flagged(self):
        self.assertEqual(redact("order 2026 total 42"), "order 2026 total 42")


class TestSanitizeEvidence(unittest.TestCase):
    def test_nested_payload_is_redacted(self):
        payload = {"rows": [{"note": "key %s" % AWS_KEY}, "a@b.co"], "meta": {"ok": True}}
        clean, receipt = sanitize_evidence(payload)
        self.assertNotIn(AWS_KEY, str(clean))
        self.assertNotIn("a@b.co", str(clean))
        self.assertGreaterEqual(receipt["redactions"]["SECRET"], 1)
        self.assertGreaterEqual(receipt["redactions"]["PII"], 1)
        self.assertFalse(receipt["clean"])

    def test_input_is_not_mutated(self):
        payload = {"note": "key %s" % AWS_KEY}
        sanitize_evidence(payload)
        self.assertIn(AWS_KEY, payload["note"])

    def test_receipt_reports_scanned_items_and_classes(self):
        clean, receipt = sanitize_evidence({"a": "plain", "b": "a@b.co"})
        self.assertEqual(receipt["scanned_items"], 2)
        self.assertEqual(receipt["classes_present"], ["PII"])
        self.assertTrue(receipt["redactions"])

    def test_clean_payload_reports_clean(self):
        clean, receipt = sanitize_evidence({"a": "plain text"})
        self.assertTrue(receipt["clean"])
        self.assertEqual(receipt["redactions"], {})

    def test_no_substring_of_secret_survives(self):
        clean, _ = sanitize_evidence({"blob": "prefix %s suffix" % AWS_KEY})
        self.assertNotIn(AWS_KEY[:16], str(clean))


class TestAssertNoSecret(unittest.TestCase):
    def test_secret_is_blocked(self):
        with self.assertRaises(SecretExfiltrationBlocked):
            assert_no_secret({"note": "key %s" % AWS_KEY})

    def test_clean_payload_passes(self):
        assert_no_secret({"note": "ordinary evidence"})

    def test_empty_payload_is_refused(self):
        with self.assertRaises(SecretExfiltrationBlocked):
            assert_no_secret({})

    def test_non_mapping_payload_is_refused(self):
        with self.assertRaises(SecretExfiltrationBlocked):
            assert_no_secret("just a string")

    def test_code_is_stable(self):
        self.assertEqual(SecretExfiltrationBlocked.code, "ERR_SECRET_EXFILTRATION_BLOCKED")


class TestDetectorSelftestClass(unittest.TestCase):
    def test_no_detector_is_vacuous_or_overflagging(self):
        receipt = detector_selftest()
        self.assertFalse(receipt["vacuous"])
        for detector in DETECTORS:
            entry = receipt[detector.detector_id]
            self.assertTrue(entry["positive_matched"], detector.detector_id)
            self.assertFalse(entry["benign_matched"], detector.detector_id)
            self.assertFalse(entry["vacuous"], detector.detector_id)


class TestClassifyMany(unittest.TestCase):
    def test_maps_each_value(self):
        self.assertEqual(classify_many({"a": "plain", "b": AWS_KEY}),
                         {"a": "PUBLIC", "b": "SECRET"})

    def test_non_mapping_returns_empty(self):
        self.assertEqual(classify_many(["a"]), {})


if __name__ == "__main__":
    unittest.main()
