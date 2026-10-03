"""Focused tests: a secret planted in a log line is redacted and the gate refuses the raw line."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from observability.redaction import (  # noqa: E402
    LogUnsafe, assert_log_safe, redact_event, redact_line,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "alice.chen@example.com"


class TestRedactLine(unittest.TestCase):
    def test_secret_is_redacted_and_reported(self):
        safe, receipt = redact_line("token %s" % AWS_KEY)
        self.assertNotIn(AWS_KEY, safe)
        self.assertIn("[REDACTED:SECRET]", safe)
        self.assertEqual(receipt["redactions"]["SECRET"], 1)
        self.assertEqual(receipt["redacted_total"], 1)
        self.assertFalse(receipt["safe"])

    def test_pii_is_redacted_and_reported(self):
        safe, receipt = redact_line("contact %s" % EMAIL)
        self.assertNotIn(EMAIL, safe)
        self.assertEqual(receipt["redactions"]["PII"], 1)
        self.assertFalse(receipt["safe"])

    def test_clean_line_is_byte_identical_and_safe(self):
        text = "workorder WO-SWOF-W2-004 checkpoint cp-1 is green"
        safe, receipt = redact_line(text)
        self.assertEqual(safe, text)
        self.assertTrue(receipt["safe"])
        self.assertEqual(receipt["redactions"], {})

    def test_no_substring_of_the_secret_survives(self):
        safe, _ = redact_line("prefix %s suffix" % AWS_KEY)
        self.assertNotIn(AWS_KEY[:16], safe)

    def test_non_string_line_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_line(None)


class TestAssertLogSafe(unittest.TestCase):
    def test_raw_secret_line_is_refused(self):
        with self.assertRaises(LogUnsafe) as caught:
            assert_log_safe("token %s" % AWS_KEY)
        self.assertEqual(caught.exception.class_name, "SECRET")
        self.assertEqual(LogUnsafe.code, "ERR_LOG_UNSAFE")

    def test_redacted_line_is_accepted(self):
        safe, _ = redact_line("token %s" % AWS_KEY)
        self.assertIsNone(assert_log_safe(safe))

    def test_empty_string_cannot_satisfy_the_gate(self):
        with self.assertRaises(LogUnsafe):
            assert_log_safe("")

    def test_whitespace_only_cannot_satisfy_the_gate(self):
        with self.assertRaises(LogUnsafe):
            assert_log_safe("   ")

    def test_non_string_cannot_satisfy_the_gate(self):
        with self.assertRaises(LogUnsafe):
            assert_log_safe(["safe looking"])

    def test_plain_string_is_accepted(self):
        self.assertIsNone(assert_log_safe("ordinary log line"))


class TestRedactEvent(unittest.TestCase):
    def test_nested_secret_is_removed(self):
        clean, receipt = redact_event({"rows": [{"note": "key %s" % AWS_KEY}], "ok": True})
        self.assertNotIn(AWS_KEY, str(clean))
        self.assertGreaterEqual(receipt["redactions"]["SECRET"], 1)
        self.assertFalse(receipt["safe"])

    def test_input_is_not_mutated(self):
        payload = {"note": "key %s" % AWS_KEY}
        redact_event(payload)
        self.assertIn(AWS_KEY, payload["note"])

    def test_empty_payload_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_event({})

    def test_unscannable_value_is_refused(self):
        with self.assertRaises(LogUnsafe):
            redact_event({"blob": object()})

    def test_clean_payload_is_safe(self):
        clean, receipt = redact_event({"note": "ordinary"})
        self.assertTrue(receipt["safe"])
        self.assertEqual(clean, {"note": "ordinary"})


if __name__ == "__main__":
    unittest.main()