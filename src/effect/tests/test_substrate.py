"""Focused tests: observation != truth, readback gating, deny-by-refusal, fail-closed finalize."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from effect.idempotency import (  # noqa: E402
    DuplicateAttemptDetected, attempt_key, plan_retry,
)
from effect.state import EffectTransitionRefused  # noqa: E402
from effect.substrate import (  # noqa: E402
    EffectRecord, EffectStateError, SuccessInferenceRefused,
    assert_no_success_inference, finalize, intend, is_success, observe, readback, reconcile,
    record_attempt,
)

PARTS = [{"part": "debit"}, {"part": "credit"}]


def intended(effect_id="eff-1", subject_id="subj-1", intent=None):
    return intend(effect_id, subject_id, intent if intent is not None else {"op": "create"},
                  environment="test")


def attempted():
    record = intended()
    return record_attempt(record, actor="agent-7", permission_allowed=True,
                          attempt_key="k1", at="2026-10-03T00:00:00Z")


def key_for(record, attempt_no):
    return attempt_key(record.effect_id, record.subject_id, record.intent_digest, attempt_no)


def observed(provider_success=True):
    return observe(attempted(), payload={"status": "ok"}, provider_success=provider_success,
                   at="2026-10-03T00:00:01Z")


class TestIntent(unittest.TestCase):
    def test_intend_freezes_digest_and_state(self):
        record = intended()
        self.assertEqual(record.state, "INTENDED")
        self.assertTrue(record.intent_digest)
        self.assertEqual(record.environment, "test")

    def test_intent_digest_ignores_later_mutation(self):
        record = observed()
        fresh = intended()
        self.assertEqual(record.intent_digest, fresh.intent_digest)
        self.assertNotEqual(record.intent_digest,
                            intended(effect_id="eff-2").intent_digest)

    def test_intent_digest_changes_with_any_input(self):
        base = intended()
        self.assertNotEqual(base.intent_digest, intended(subject_id="subj-2").intent_digest)
        self.assertNotEqual(base.intent_digest,
                            intended(intent={"op": "update"}).intent_digest)

    def test_blank_identity_is_refused(self):
        with self.assertRaises(EffectStateError):
            intend("", "subj-1", {"op": "create"})


class TestObserveIsNotSuccess(unittest.TestCase):
    def test_observe_moves_attempted_to_observed(self):
        self.assertEqual(observed().state, "OBSERVED")

    def test_provider_success_true_is_not_success(self):
        record = observed(provider_success=True)
        self.assertFalse(is_success(record))
        self.assertNotEqual(record.state, "RECONCILED")
        self.assertTrue(record.provider_success)
        with self.assertRaises(SuccessInferenceRefused):
            assert_no_success_inference(record)

    def test_observe_from_intended_is_refused(self):
        with self.assertRaises(Exception):
            observe(intended(), payload={}, provider_success=True, at="t")


class TestReadbackGating(unittest.TestCase):
    def test_readback_records_evidence(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t")
        self.assertEqual(record.state, "READBACK")
        self.assertTrue(record.readbacks[-1].matches_expected)

    def test_wrong_subject_readback_is_refused(self):
        with self.assertRaises(EffectStateError) as ctx:
            readback(observed(), payload={"subject_id": "subj-2", "op": "create"},
                     expected={"op": "create"}, at="t")
        self.assertEqual(ctx.exception.reason_code, "WRONG_SUBJECT_READBACK")
        self.assertEqual(EffectStateError.code, "ERR_EFFECT_STATE")

    def test_ambiguous_readback_cannot_reconcile(self):
        record = observe(attempted(), payload={"s": "?"}, provider_success=None, at="t")
        record = readback(record, payload={"s": "?"}, expected=None, at="t")
        self.assertIsNone(record.readbacks[-1].matches_expected)
        self.assertEqual(reconcile(record, at="t").state, "UNKNOWN_EFFECT")


class TestReconcile(unittest.TestCase):
    def test_fresh_match_reconciles(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t")
        reconciled = reconcile(record, at="t")
        self.assertEqual(reconciled.state, "RECONCILED")
        self.assertTrue(is_success(reconciled))
        self.assertIsNone(assert_no_success_inference(reconciled))

    def test_no_readback_fails_closed(self):
        reconciled = reconcile(observed(), at="t")
        self.assertEqual(reconciled.state, "UNKNOWN_EFFECT")
        self.assertEqual(reconciled.reason_code, "NO_READBACK_FAIL_CLOSED")

    def test_stale_readback_fails_closed(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t", stale=True)
        reconciled = reconcile(record, at="t")
        self.assertEqual(reconciled.state, "UNKNOWN_EFFECT")
        self.assertEqual(reconciled.reason_code, "STALE_READBACK_FAIL_CLOSED")

    def test_mismatch_fails_closed(self):
        record = readback(observed(), payload={"op": "other"}, expected={"op": "create"}, at="t")
        reconciled = reconcile(record, at="t")
        self.assertEqual(reconciled.state, "UNKNOWN_EFFECT")
        self.assertEqual(reconciled.reason_code, "RECONCILIATION_MISMATCH")

    def test_provider_claim_is_never_consulted(self):
        record = observe(attempted(), payload={"status": "ok"}, provider_success=True, at="t")
        self.assertEqual(reconcile(record, at="t").state, "UNKNOWN_EFFECT")


class TestFinalize(unittest.TestCase):
    def test_finalize_never_raises(self):
        for record in (intended(), attempted(), observed(False)):
            self.assertIsInstance(finalize(record), EffectRecord)

    def test_finalize_converts_unresolved_to_unknown(self):
        record = finalize(attempted())
        self.assertEqual(record.state, "UNKNOWN_EFFECT")
        self.assertEqual(record.reason_code, "UNRESOLVED_EFFECT_FAIL_CLOSED")

    def test_finalize_provider_success_without_readback(self):
        record = finalize(observed(True))
        self.assertEqual(record.state, "UNKNOWN_EFFECT")
        self.assertEqual(record.reason_code, "NO_READBACK_AFTER_PROVIDER_SUCCESS")

    def test_finalize_never_returns_unjustified_success(self):
        self.assertFalse(is_success(finalize(observed(True))))
        self.assertFalse(is_success(finalize(attempted())))

    def test_finalize_keeps_a_justified_success(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t")
        reconciled = reconcile(record, at="t")
        self.assertEqual(finalize(reconciled).state, "RECONCILED")


class TestRetryThroughPublicApi(unittest.TestCase):
    def test_retry_end_to_end_reaches_reconciled(self):
        record = intended()
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 1), at="t0")
        record = observe(record, payload={"status": "denied"}, provider_success=False, at="t1")
        record = readback(record, payload={"op": "other"}, expected={"op": "create"}, at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "UNKNOWN_EFFECT")
        plan = plan_retry(record)
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.next_attempt_no, 2)
        self.assertEqual(plan.idempotency_key, key_for(record, 2))
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=plan.idempotency_key, at="t4")
        self.assertEqual(record.state, "ATTEMPTED")
        self.assertEqual(len(record.attempts), 2)
        record = observe(record, payload={"status": "ok"}, provider_success=True, at="t5")
        record = readback(record, payload={"op": "create"}, expected={"op": "create"}, at="t6")
        record = reconcile(record, at="t7")
        self.assertEqual(record.state, "RECONCILED")
        self.assertTrue(is_success(record))
        self.assertEqual(len(record.attempts), 2)

    def test_retry_drops_the_superseded_observation_cycle(self):
        record = observe(attempted(), payload={"status": "ok"}, provider_success=True, at="t1")
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 2), at="t2")
        self.assertEqual(record.state, "ATTEMPTED")
        self.assertEqual(len(record.attempts), 2)
        self.assertEqual(record.observations, ())
        self.assertEqual(record.readbacks, ())
        self.assertIsNone(record.provider_success)

    def test_retry_from_readback_state_is_recordable(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t2")
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 2), at="t3")
        self.assertEqual(record.state, "ATTEMPTED")
        self.assertEqual(len(record.attempts), 2)

    def test_retry_from_unknown_effect_is_recordable(self):
        record = finalize(attempted())
        self.assertEqual(record.state, "UNKNOWN_EFFECT")
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 2), at="t2")
        self.assertEqual(record.state, "ATTEMPTED")
        self.assertEqual(len(record.attempts), 2)

    def test_retry_from_partial_effect_is_recordable(self):
        record = record_attempt(intended(intent={"op": "transfer", "parts": PARTS}),
                                actor="agent-7", permission_allowed=True, attempt_key="k1",
                                at="t0")
        record = observe(record, payload={"part": "debit"}, provider_success=True, at="t1")
        record = readback(record, payload={"part": "debit"}, expected=PARTS, at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "PARTIAL_EFFECT")
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 2), at="t4")
        self.assertEqual(record.state, "ATTEMPTED")
        self.assertEqual(len(record.attempts), 2)

    def test_retry_with_existing_key_still_raises(self):
        record = intended()
        record = record_attempt(record, actor="agent-7", permission_allowed=True,
                                attempt_key=key_for(record, 1), at="t0")
        record = observe(record, payload={"status": "ok"}, provider_success=True, at="t1")
        with self.assertRaises(DuplicateAttemptDetected):
            record_attempt(record, actor="agent-7", permission_allowed=True,
                           attempt_key=key_for(record, 1), at="t2")

    def test_reconciled_record_cannot_be_retried(self):
        record = readback(observed(), payload={"op": "create"}, expected={"op": "create"},
                          at="t2")
        record = reconcile(record, at="t3")
        self.assertEqual(record.state, "RECONCILED")
        with self.assertRaises(EffectTransitionRefused):
            record_attempt(record, actor="agent-7", permission_allowed=True,
                           attempt_key=key_for(record, 2), at="t4")


if __name__ == "__main__":
    unittest.main()
