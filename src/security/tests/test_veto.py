"""Focused tests: any active veto signal vetoes and proxies can never clear it."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from security.veto import (  # noqa: E402
    PROXY_SIGNALS, VETO_SIGNALS, SecurityVeto, SecurityVetoActive, VetoDecision,
)


class TestVetoSignals(unittest.TestCase):
    def setUp(self):
        self.veto = SecurityVeto()

    def test_no_signal_is_not_vetoed(self):
        decision = self.veto.evaluate({})
        self.assertFalse(decision.vetoed)
        self.assertEqual(decision.reason_code, "OK")

    def test_any_single_active_signal_vetoes(self):
        for signal in sorted(VETO_SIGNALS):
            with self.subTest(signal=signal):
                decision = self.veto.evaluate({signal: True})
                self.assertTrue(decision.vetoed)
                self.assertIn(signal, decision.active_signals)

    def test_literal_false_means_not_active(self):
        self.assertFalse(self.veto.evaluate({"secret_exposure": False}).vetoed)

    def test_unknown_signal_fails_closed(self):
        decision = self.veto.evaluate({"mystery_signal": True})
        self.assertTrue(decision.vetoed)
        self.assertEqual(decision.reason_code, "UNKNOWN_SIGNAL_FAIL_CLOSED")

    def test_ambiguous_truthy_string_is_active(self):
        decision = self.veto.evaluate({"secret_exposure": "true"})
        self.assertTrue(decision.vetoed)
        self.assertEqual(decision.reason_code, "AMBIGUOUS_SIGNAL_FAIL_CLOSED")

    def test_ambiguous_none_is_active(self):
        decision = self.veto.evaluate({"secret_exposure": None})
        self.assertTrue(decision.vetoed)
        self.assertEqual(decision.reason_code, "AMBIGUOUS_SIGNAL_FAIL_CLOSED")

    def test_iterable_of_names_is_active(self):
        self.assertTrue(self.veto.evaluate(["secret_exposure"]).vetoed)

    def test_unknown_container_fails_closed(self):
        self.assertTrue(self.veto.evaluate("secret_exposure").vetoed)

    def test_assert_not_vetoed_raises(self):
        decision = self.veto.evaluate({"secret_exposure": True})
        with self.assertRaises(SecurityVetoActive) as ctx:
            self.veto.assert_not_vetoed(decision)
        self.assertIn("secret_exposure", str(ctx.exception))

    def test_assert_not_vetoed_returns_clean_decision(self):
        decision = self.veto.evaluate({})
        self.assertIs(self.veto.assert_not_vetoed(decision), decision)

    def test_assert_not_vetoed_fails_closed_on_unknown_object(self):
        with self.assertRaises(SecurityVetoActive):
            self.veto.assert_not_vetoed(object())

    def test_code_is_stable(self):
        self.assertEqual(SecurityVetoActive.code, "ERR_SECURITY_VETO_ACTIVE")


class TestProxyCannotOverride(unittest.TestCase):
    def setUp(self):
        self.veto = SecurityVeto()

    def test_all_proxies_green_with_one_veto_stays_vetoed(self):
        proxies = {name: True for name in sorted(PROXY_SIGNALS)}
        decision = self.veto.evaluate_with_proxies({"secret_exposure": True}, proxies)
        self.assertTrue(decision.vetoed)
        self.assertEqual(decision.reason_code, "VETO_ACTIVE_PROXIES_IGNORED")
        self.assertTrue(decision.proxy_cannot_override)
        self.assertEqual(set(decision.proxies_ignored), set(PROXY_SIGNALS))

    def test_proxies_are_recorded_even_when_clean(self):
        decision = self.veto.evaluate_with_proxies({}, {"ci_green": True})
        self.assertFalse(decision.vetoed)
        self.assertEqual(decision.proxies_ignored, ("ci_green",))

    def test_proxy_signal_in_signals_is_not_a_veto(self):
        decision = self.veto.evaluate({"test_green": True})
        self.assertFalse(decision.vetoed)

    def test_ambiguous_proxy_value_is_not_a_veto(self):
        decision = self.veto.evaluate({"test_green": "true"})
        self.assertFalse(decision.vetoed)
        self.assertEqual(decision.proxies_ignored, ("test_green",))

    def test_veto_decision_is_frozen(self):
        decision = self.veto.evaluate({})
        self.assertIsInstance(decision, VetoDecision)
        with self.assertRaises(Exception):
            decision.vetoed = True


if __name__ == "__main__":
    unittest.main()
