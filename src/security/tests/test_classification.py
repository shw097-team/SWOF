"""Focused tests: secret/PII classification, redaction and the evidence no-secret gate."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.classification import (  # noqa: E402
    BENIGN_SAMPLES, CLASSES, DETECTORS, REAL_WORLD_SECRET_SAMPLES, SecretExfiltrationBlocked,
    assert_no_secret, classify, classify_many, detector_selftest, redact,
    sanitize_evidence,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SESSION_KEY = "ASIAIOSFODNN7EXAMPLE"
BEARER = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD"
AWS_SECRET = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_PAT = "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwx"
GITLAB_PAT = "glpat-abcdefghij1234567890"
SLACK_TOKEN = "xoxb-123456789012-1234567890123-AbCdEfGhIjKl"
STRIPE_KEY = "sk_live_51H8xYzAbCdEfGhIjKlMnOpQr"
SSH_BLOB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7"
JSON_ACCESS = '{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD"}'
JSON_TOKEN = '{"token":"abcdefghij1234567890"}'
JSON_API_KEY = '{"api_key":"sk-proj-abcdefghij1234567890"}'

PLANTED_SHAPES = (
    BEARER,
    "Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Ng==",
    AWS_SECRET,
    GITHUB_PAT,
    GITLAB_PAT,
    SLACK_TOKEN,
    STRIPE_KEY,
    JSON_ACCESS,
    JSON_TOKEN,
    JSON_API_KEY,
    AWS_SESSION_KEY,
    SSH_BLOB,
    "-----BEGIN RSA PRIVATE KEY-----",
)


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


class TestPlantSecretShapes(unittest.TestCase):
    def test_every_planted_shape_classifies_secret(self):
        for sample in PLANTED_SHAPES:
            self.assertEqual(classify(sample), "SECRET", sample)

    def test_every_planted_shape_is_redacted(self):
        for sample in PLANTED_SHAPES:
            self.assertIn("[REDACTED:SECRET]", redact(sample), sample)

    def test_every_planted_shape_is_blocked_by_the_gate(self):
        for sample in PLANTED_SHAPES:
            with self.assertRaises(SecretExfiltrationBlocked):
                assert_no_secret({"evidence": sample})

    def test_bearer_header_shape(self):
        self.assertEqual(classify(BEARER), "SECRET")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redact(BEARER))

    def test_aws_secret_access_key_assignment(self):
        self.assertEqual(classify(AWS_SECRET), "SECRET")
        self.assertNotIn("wJalrXUtnFEMI", redact(AWS_SECRET))

    def test_vendor_prefixed_tokens(self):
        for sample in (GITHUB_PAT, GITLAB_PAT, SLACK_TOKEN, STRIPE_KEY):
            self.assertEqual(classify(sample), "SECRET", sample)
            self.assertEqual(redact(sample), "[REDACTED:SECRET]", sample)

    def test_aws_session_key_shape(self):
        self.assertEqual(classify(AWS_SESSION_KEY), "SECRET")
        self.assertEqual(redact("id " + AWS_SESSION_KEY), "id [REDACTED:SECRET]")

    def test_ssh_public_key_blob(self):
        self.assertEqual(classify(SSH_BLOB), "SECRET")
        self.assertNotIn("AAAAB3NzaC1yc2E", redact(SSH_BLOB))

    def test_json_key_value_pair_is_caught(self):
        for sample in (JSON_ACCESS, JSON_TOKEN, JSON_API_KEY):
            self.assertEqual(classify(sample), "SECRET", sample)
            self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redact(sample))

    def test_json_mapping_value_is_redacted_and_blocked(self):
        payload = {"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD"}
        clean, receipt = sanitize_evidence(payload)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", str(clean))
        self.assertIn("SECRET", receipt["classes_present"])
        with self.assertRaises(SecretExfiltrationBlocked):
            assert_no_secret(payload)

    def test_planted_shapes_still_leaves_benign_text_public(self):
        for sample in BENIGN_SAMPLES:
            self.assertEqual(classify(sample), "PUBLIC", sample)
            self.assertEqual(redact(sample), sample)

    def test_real_world_sample_table_is_fully_covered(self):
        self.assertEqual(set(PLANTED_SHAPES), set(REAL_WORLD_SECRET_SAMPLES))


class TestDetectorSelftestReceiptFlags(unittest.TestCase):
    def test_selftest_reports_all_three_flags_per_detector(self):
        receipt = detector_selftest()
        for detector in DETECTORS:
            entry = receipt[detector.detector_id]
            for flag in ("positive_matched", "true_negative_matched", "vacuous"):
                self.assertIn(flag, entry, detector.detector_id)
            self.assertTrue(entry["positive_matched"], detector.detector_id)
            self.assertTrue(entry["true_negative_matched"], detector.detector_id)
            self.assertFalse(entry["vacuous"], detector.detector_id)

    def test_selftest_covers_real_world_and_benign_samples(self):
        receipt = detector_selftest()
        self.assertEqual(receipt["missed_secret_samples"], [])
        self.assertEqual(receipt["unredacted_secret_samples"], [])
        self.assertEqual(receipt["flagged_benign_samples"], [])

    def test_selftest_refuses_when_a_detector_is_vacuous(self):
        import re

        from security import classification

        broken = classification._Detector(
            "SECRET", "broken_never_match",
            re.compile(r"THIS_PATTERN_NEVER_OCCURS_ANYWHERE"),
            "a positive that cannot match",
            "a benign sample")
        original = classification.DETECTORS
        classification.DETECTORS = original + (broken,)
        try:
            with self.assertRaises(SecretExfiltrationBlocked):
                classification.detector_selftest()
        finally:
            classification.DETECTORS = original

    def test_selftest_refuses_when_a_benign_sample_is_flagged(self):
        from security import classification

        original = classification.BENIGN_SAMPLES
        classification.BENIGN_SAMPLES = original + (AWS_KEY,)
        try:
            with self.assertRaises(SecretExfiltrationBlocked):
                classification.detector_selftest()
        finally:
            classification.BENIGN_SAMPLES = original


class TestUnscannableBytes(unittest.TestCase):
    def test_bytes_scalar_is_blocked_by_the_gate(self):
        with self.assertRaises(SecretExfiltrationBlocked):
            assert_no_secret({"blob": b"Authorization: Bearer " + b"x" * 32})

    def test_bytearray_scalar_is_blocked_by_the_gate(self):
        with self.assertRaises(SecretExfiltrationBlocked):
            assert_no_secret({"blob": bytearray(b"plain-ascii-bytes")})

    def test_bytes_scalar_is_replaced_and_reported_unscannable(self):
        clean, receipt = sanitize_evidence({"blob": b"prefix " + AWS_KEY.encode()})
        self.assertNotIn("AKIA", str(clean))
        self.assertIn("[REDACTED:UNSCANNABLE_BYTES]", str(clean))
        self.assertFalse(receipt["clean"])
        self.assertEqual(receipt["unscannable_bytes"], 1)

    def test_nested_bytes_scalar_is_counted(self):
        clean, receipt = sanitize_evidence({"rows": [{"raw": b"secret-bytes"}, "plain"]})
        self.assertEqual(receipt["unscannable_bytes"], 1)
        self.assertIn("[REDACTED:UNSCANNABLE_BYTES]", str(clean))

    def test_ordinary_scalars_are_not_flagged(self):
        payload = {"n": 42, "f": 3.5, "b": True, "none": None, "s": "plain text"}
        clean, receipt = sanitize_evidence(payload)
        self.assertTrue(receipt["clean"])
        self.assertEqual(receipt["unscannable_bytes"], 0)
        self.assertEqual(clean, payload)
        assert_no_secret(payload)


if __name__ == "__main__":
    unittest.main()
