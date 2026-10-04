"""Focused tests: attempt-key identity, duplicate refusal, retry ceiling, reobserve-not-retry."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from effect.idempotency import (  # noqa: E402
    DuplicateAttemptDetected, RetryPlan, RetryRefused, assert_retryable, attempt_key,
    classify_retry, plan_reobserve, plan_retry,
)
from effect.substrate import intend, observe, readback, reconcile, record_attempt  # noqa: E402


def new_intent():
    return intend("eff-1", "subj-1", {"op": "create"})


def key_for(record, attempt_no):
    return attempt_key(record.effect_id, record.subject_id, record.intent_digest, attempt_no)


def attempted():
    record = new_intent()
    return record_attempt(record, actor="agent-7", permission_allowed=True,
                          attempt_key=key_for(record, 1), at="t0")


def as_state(record, state, reason_code=""):
    return record.__class__(**{**record.__dict__, "state": state, "reason_code": reason_code})


class TestAttemptKey(unittest.TestCase):
    def test_key_is_deterministic(self):
        first = attempt_key("eff-1", "subj-1", "digest", 1)
        self.assertEqual(first, attempt_key("eff-1", "subj-1", "digest", 1))
        self.assertEqual(len(first), 64)
        int(first, 16)

    def test_key_depends_on_every_input(self):
        base = attempt_key("eff-1", "subj-1", "digest", 1)
        self.assertNotEqual(base, attempt_key("eff-2", "subj-1", "digest", 1))
        self.assertNotEqual(base, attempt_key("eff-1", "subj-2", "digest", 1))
        self.assertNotEqual(base, attempt_key("eff-1", "subj-1", "other", 1))
        self.assertNotEqual(base, attempt_key("eff-1", "subj-1", "digest", 2))

    def test_bad_attempt_no_is_refused(self):
        with self.assertRaises(ValueError):
            attempt_key("eff-1", "subj-1", "digest", 0)


class TestDuplicate(unittest.TestCase):
    def test_existing_key_is_duplicate(self):
        self.assertEqual(classify_retry(attempted(), attempt_no=1), "DUPLICATE")

    def test_mid_flight_key_is_refused_not_new(self):
        self.assertEqual(classify_retry(attempted(), attempt_no=2), "REFUSED")

    def test_duplicate_attempt_raises(self):
        with self.assertRaises(DuplicateAttemptDetected) as ctx:
            assert_retryable(attempted(), attempt_no=1)
        self.assertEqual(DuplicateAttemptDetected.code, "ERR_DUPLICATE_ATTEMPT")

    def test_second_attempt_with_existing_key_raises(self):
        record = attempted()
        with self.assertRaises(DuplicateAttemptDetected):
            record_attempt(record, actor="agent-7", permission_allowed=True,
                           attempt_key=key_for(record, 1), at="t1")


class TestMidFlightRetryRefused(unittest.TestCase):
    def test_plan_retry_refuses_attempted(self):
        plan = plan_retry(attempted())
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "RETRY_REFUSED_MID_FLIGHT")

    def test_plan_retry_refuses_observed(self):
        record = observe(attempted(), payload={"status": "ok"}, provider_success=True, at="t1")
        self.assertEqual(record.state, "OBSERVED")
        plan = plan_retry(record)
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "RETRY_REFUSED_MID_FLIGHT")

    def test_plan_retry_refuses_readback(self):
        record = readback(observe(attempted(), payload={"status": "ok"},
                                  provider_success=True, at="t1"),
                          payload={"op": "create"}, expected={"op": "create"}, at="t2")
        self.assertEqual(record.state, "READBACK")
        plan = plan_retry(record)
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "RETRY_REFUSED_MID_FLIGHT")

    def test_assert_retryable_raises_for_mid_flight(self):
        with self.assertRaises(RetryRefused):
            assert_retryable(attempted(), attempt_no=2)

    def test_classify_retry_refuses_mid_flight(self):
        self.assertEqual(classify_retry(attempted(), attempt_no=2), "REFUSED")


class TestRetryRefusals(unittest.TestCase):
    def test_retry_reconciled_is_refused(self):
        record = readback(observe(attempted(), payload={"op": "create"},
                                  provider_success=True, at="t1"),
                          payload={"op": "create"}, expected={"op": "create"}, at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "RECONCILED")
        with self.assertRaises(RetryRefused):
            assert_retryable(record, attempt_no=2)

    def test_retry_denied_is_refused(self):
        denied = record_attempt(new_intent(), actor="a", permission_allowed=False,
                                attempt_key="k1", at="t0")
        self.assertEqual(denied.state, "DENIED")
        with self.assertRaises(RetryRefused):
            assert_retryable(denied, attempt_no=1)

    def test_retry_irreversible_is_refused(self):
        record = as_state(attempted(), "IRREVERSIBLE")
        with self.assertRaises(RetryRefused):
            assert_retryable(record, attempt_no=2)

    def test_retry_ceiling_is_hard(self):
        with self.assertRaises(RetryRefused):
            assert_retryable(attempted(), attempt_no=5, max_retries=3)
        self.assertEqual(RetryRefused.code, "ERR_RETRY_REFUSED")

    def test_plan_retry_allows_retry_of_uncertain(self):
        record = as_state(attempted(), "UNKNOWN_EFFECT", "NO_READBACK_FAIL_CLOSED")
        plan = plan_retry(record)
        self.assertIsInstance(plan, RetryPlan)
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.next_attempt_no, 2)
        self.assertTrue(plan.idempotency_key)

    def test_plan_retry_refuses_reconciled(self):
        record = as_state(attempted(), "RECONCILED")
        plan = plan_retry(record)
        self.assertFalse(plan.allowed)
        self.assertIn("RECONCILED", plan.reason_code)

    def test_plan_retry_refuses_when_ceiling_reached(self):
        record = as_state(attempted(), "UNKNOWN_EFFECT")
        plan = plan_retry(record, max_retries=1)
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "RETRY_LIMIT_EXCEEDED")


class TestReobserve(unittest.TestCase):
    def test_reobserve_for_unknown_effect(self):
        record = as_state(attempted(), "UNKNOWN_EFFECT")
        decision = plan_reobserve(record)
        self.assertTrue(decision["reobserve"])
        self.assertIn("UNKNOWN_EFFECT", decision["reason_code"])

    def test_reobserve_for_partial_effect(self):
        decision = plan_reobserve(as_state(attempted(), "PARTIAL_EFFECT"))
        self.assertTrue(decision["reobserve"])

    def test_no_reobserve_for_reconciled(self):
        self.assertFalse(plan_reobserve(as_state(attempted(), "RECONCILED"))["reobserve"])


class TestPartialEffectNotRetryable(unittest.TestCase):
    def test_plan_retry_refuses_partial_effect(self):
        record = as_state(attempted(), "PARTIAL_EFFECT", "PARTIAL_EFFECT_DETECTED")
        plan = plan_retry(record)
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "RETRY_REFUSED_PARTIAL_EFFECT")

    def test_assert_retryable_raises_for_partial_effect(self):
        record = as_state(attempted(), "PARTIAL_EFFECT", "PARTIAL_EFFECT_DETECTED")
        with self.assertRaises(RetryRefused):
            assert_retryable(record, attempt_no=2)

    def test_classify_retry_refuses_partial_effect(self):
        record = as_state(attempted(), "PARTIAL_EFFECT", "PARTIAL_EFFECT_DETECTED")
        self.assertEqual(classify_retry(record, attempt_no=2), "REFUSED")

    def test_unknown_effect_retry_is_still_reachable(self):
        record = as_state(attempted(), "UNKNOWN_EFFECT", "NO_READBACK_FAIL_CLOSED")
        plan = plan_retry(record)
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.reason_code, "RETRY_ALLOWED")


if __name__ == "__main__":
    unittest.main()
