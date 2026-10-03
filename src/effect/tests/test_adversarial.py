"""Adversarial suite: each case asserts its exact typed error or terminal state.

These are the failure modes that would let an unverified effect be recorded as success. Every
one must fail closed: an OBSERVATION never becomes truth, uncertainty is terminal, a duplicate
side effect is refused, and an irreversible effect cannot be silently compensated.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from effect.compensation import (  # noqa: E402
    IrreversibleEffect, assert_compensable, plan_compensation,
)
from effect.idempotency import (  # noqa: E402
    DuplicateAttemptDetected, RetryRefused, assert_retryable, attempt_key, plan_retry,
)
from effect.state import EffectTransitionRefused, assert_transition  # noqa: E402
from effect.substrate import (  # noqa: E402
    EffectStateError, SuccessInferenceRefused, assert_no_success_inference, finalize, intend,
    is_success, observe, readback, reconcile, record_attempt,
)

PARTS = [{"part": "debit"}, {"part": "credit"}]


def intended(intent=None):
    return intend("eff-1", "subj-1", intent if intent is not None else {"op": "create"},
                  environment="test")


def key_for(record, attempt_no):
    return attempt_key(record.effect_id, record.subject_id, record.intent_digest, attempt_no)


def attempted():
    record = intended()
    return record_attempt(record, actor="agent-7", permission_allowed=True,
                          attempt_key=key_for(record, 1), at="t0")


def observed(provider_success=True, payload=None, record=None):
    return observe(record if record is not None else attempted(),
                   payload=payload if payload is not None else {"status": "ok"},
                   provider_success=provider_success, at="t1")


class TestAdversarial(unittest.TestCase):
    def test_01_apparent_success_with_no_readback(self):
        record = observed(provider_success=True)
        reconciled = reconcile(record, at="t2")
        self.assertEqual(reconciled.state, "UNKNOWN_EFFECT")
        self.assertEqual(reconciled.reason_code, "NO_READBACK_FAIL_CLOSED")
        self.assertFalse(is_success(reconciled))

    def test_02_ambiguous_provider_response_stays_unknown(self):
        record = observed(provider_success=None, payload={"status": "unknown"})
        self.assertIsNone(record.provider_success)
        self.assertEqual(reconcile(record, at="t2").state, "UNKNOWN_EFFECT")
        record = readback(record, payload={"status": "pending"}, expected=None, at="t2")
        self.assertIsNone(record.readbacks[-1].matches_expected)
        self.assertEqual(finalize(record).state, "UNKNOWN_EFFECT")

    def test_03_duplicate_retry_is_refused(self):
        with self.assertRaises(DuplicateAttemptDetected):
            assert_retryable(attempted(), attempt_no=1)
        with self.assertRaises(DuplicateAttemptDetected):
            record_attempt(attempted(), actor="agent-7", permission_allowed=True,
                           attempt_key=key_for(attempted(), 1), at="t1")

    def test_04_partial_effect_yields_compensation_pointer(self):
        record = record_attempt(intended({"op": "transfer", "parts": PARTS}), actor="agent-7",
                                permission_allowed=True, attempt_key="k1", at="t0")
        record = observe(record, payload={"part": "debit"}, provider_success=True, at="t1")
        record = readback(record, payload={"part": "debit"}, expected=PARTS, at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "PARTIAL_EFFECT")
        self.assertEqual(record.reason_code, "PARTIAL_EFFECT_DETECTED")
        pointer = plan_compensation(record, registry={"eff-1": {"kind": "ROLLBACK",
                                                               "ref": "comp-0001"}})
        self.assertTrue(pointer.compensable)
        self.assertEqual(pointer.ref, "comp-0001")

    def test_05_stale_readback_fails_closed(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t2", stale=True)
        reconciled = reconcile(record, at="t3")
        self.assertEqual(reconciled.state, "UNKNOWN_EFFECT")
        self.assertEqual(reconciled.reason_code, "STALE_READBACK_FAIL_CLOSED")

    def test_06_wrong_subject_readback_is_refused(self):
        with self.assertRaises(EffectStateError) as ctx:
            readback(observed(), payload={"subject_id": "subj-2", "op": "create"},
                     expected={"op": "create"}, at="t2")
        self.assertEqual(ctx.exception.reason_code, "WRONG_SUBJECT_READBACK")
        self.assertEqual(EffectStateError.code, "ERR_EFFECT_STATE")

    def test_07_reconciliation_mismatch_fails_closed(self):
        record = readback(observed(), payload={"op": "other"}, expected={"op": "create"},
                          at="t2")
        reconciled = reconcile(record, at="t3")
        self.assertEqual(reconciled.state, "UNKNOWN_EFFECT")
        self.assertEqual(reconciled.reason_code, "RECONCILIATION_MISMATCH")

    def test_08_denied_permission_records_no_attempt_and_no_success(self):
        record = record_attempt(intended(), actor="agent-7", permission_allowed=False,
                                attempt_key="k1", at="t0")
        self.assertEqual(record.state, "DENIED")
        self.assertEqual(record.reason_code, "PERMISSION_DENIED")
        self.assertEqual(record.attempts, ())
        with self.assertRaises(SuccessInferenceRefused):
            assert_no_success_inference(record)

    def test_09_observed_to_reconciled_transition_is_refused(self):
        with self.assertRaises(EffectTransitionRefused):
            assert_transition("OBSERVED", "RECONCILED")
        self.assertEqual(EffectTransitionRefused.code, "ERR_EFFECT_TRANSITION_REFUSED")

    def test_10_irreversible_effect_raises_from_assert_compensable(self):
        record = record_attempt(intended({"op": "send"}), actor="agent-7",
                                permission_allowed=True, attempt_key="k1", at="t0")
        pointer = plan_compensation(record, irreversible_attempts=("eff-1",))
        self.assertFalse(pointer.compensable)
        self.assertEqual(pointer.reason_code, "IRREVERSIBLE_EFFECT")
        with self.assertRaises(IrreversibleEffect):
            assert_compensable(pointer)

    def test_11_retry_of_reconciled_effect_is_refused(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "RECONCILED")
        with self.assertRaises(RetryRefused):
            assert_retryable(record, attempt_no=2)
        self.assertEqual(RetryRefused.code, "ERR_RETRY_REFUSED")

    def test_12_finalize_never_returns_unjustified_success(self):
        for record in (intended(), attempted(), observed(True), observed(False)):
            swept = finalize(record)
            self.assertFalse(is_success(swept))
            self.assertEqual(swept.state, "UNKNOWN_EFFECT")
        stale = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                         at="t2", stale=True)
        self.assertFalse(is_success(finalize(stale)))

    def test_13_retry_is_recordable_through_the_public_api(self):
        record = intended()
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 1), at="t0")
        record = observe(record, payload={"status": "denied"}, provider_success=False, at="t1")
        record = readback(record, payload={"op": "other"}, expected={"op": "create"}, at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "UNKNOWN_EFFECT")
        plan = plan_retry(record)
        self.assertTrue(plan.allowed)
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=plan.idempotency_key, at="t4")
        self.assertEqual(record.state, "ATTEMPTED")
        self.assertEqual(len(record.attempts), 2)
        record = observe(record, payload={"status": "ok"}, provider_success=True, at="t5")
        record = readback(record, payload={"op": "create"}, expected={"op": "create"}, at="t6")
        record = reconcile(record, at="t7")
        self.assertEqual(record.state, "RECONCILED")
        self.assertTrue(is_success(record))

    def test_14_reconciled_record_cannot_be_retried_through_the_public_api(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "RECONCILED")
        with self.assertRaises(EffectTransitionRefused):
            record_attempt(record, actor="agent-7", permission_allowed=True,
                           attempt_key=key_for(record, 2), at="t4")
        with self.assertRaises(RetryRefused):
            assert_retryable(record, attempt_no=2)


if __name__ == "__main__":
    unittest.main()
