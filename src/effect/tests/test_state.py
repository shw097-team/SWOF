"""Focused tests: the closed state alphabet, the missing OBSERVED->RECONCILED edge, DENIED entry."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from effect.state import (  # noqa: E402
    ALLOWED_TRANSITIONS, EFFECT_STATES, INTENT_STATES, TERMINAL_STATES,
    EffectTransitionRefused, assert_transition, is_terminal, is_unknown, state_rank,
)


class TestAlphabet(unittest.TestCase):
    def test_effect_states_is_intent_plus_terminal(self):
        self.assertEqual(EFFECT_STATES, INTENT_STATES + TERMINAL_STATES)

    def test_unknown_state_raises_even_for_a_query(self):
        with self.assertRaises(EffectTransitionRefused):
            is_terminal("MOSTLY_DONE")
        with self.assertRaises(EffectTransitionRefused):
            is_unknown("PARTIAL")
        with self.assertRaises(EffectTransitionRefused):
            state_rank("RECONCILED ")

    def test_unknown_state_raises_on_assert_transition(self):
        with self.assertRaises(EffectTransitionRefused):
            assert_transition("INTENDED", "SUCCEEDED")

    def test_terminal_states_are_terminal(self):
        for state in TERMINAL_STATES:
            self.assertTrue(is_terminal(state), state)

    def test_intent_states_are_not_terminal(self):
        for state in INTENT_STATES:
            self.assertFalse(is_terminal(state), state)

    def test_unknown_states_are_unknown_and_terminal(self):
        self.assertTrue(is_unknown("UNKNOWN_EFFECT"))
        self.assertTrue(is_unknown("PARTIAL_EFFECT"))
        self.assertTrue(is_terminal("UNKNOWN_EFFECT"))

    def test_rank_is_stable_and_ordered(self):
        self.assertEqual(state_rank("INTENDED"), 0)
        self.assertEqual(state_rank("READBACK"), 3)
        self.assertEqual(state_rank("INTENDED"), state_rank("INTENDED"))


class TestMissingTruthEdge(unittest.TestCase):
    def test_observed_to_reconciled_is_refused(self):
        with self.assertRaises(EffectTransitionRefused):
            assert_transition("OBSERVED", "RECONCILED")

    def test_observed_reconciled_is_not_in_the_table(self):
        self.assertNotIn("RECONCILED", ALLOWED_TRANSITIONS["OBSERVED"])

    def test_only_readback_reaches_reconciled(self):
        sources = {src for src, dsts in ALLOWED_TRANSITIONS.items() if "RECONCILED" in dsts}
        self.assertEqual(sources, {"READBACK"})

    def test_observed_to_readback_is_allowed(self):
        self.assertEqual(assert_transition("OBSERVED", "READBACK"), ("OBSERVED", "READBACK"))

    def test_readback_to_reconciled_is_allowed(self):
        self.assertEqual(assert_transition("READBACK", "RECONCILED"),
                         ("READBACK", "RECONCILED"))

    def test_readback_to_unknown_is_allowed(self):
        self.assertEqual(assert_transition("READBACK", "UNKNOWN_EFFECT"),
                         ("READBACK", "UNKNOWN_EFFECT"))


class TestDeniedAndTerminal(unittest.TestCase):
    def test_denied_only_from_intended(self):
        sources = {src for src, dsts in ALLOWED_TRANSITIONS.items() if "DENIED" in dsts}
        self.assertEqual(sources, {"INTENDED"})

    def test_denied_is_terminal_and_rejects_further(self):
        self.assertEqual(ALLOWED_TRANSITIONS["DENIED"], frozenset())
        with self.assertRaises(EffectTransitionRefused):
            assert_transition("DENIED", "ATTEMPTED")

    def test_terminal_states_reject_all_transitions(self):
        for state in TERMINAL_STATES:
            if state == "PARTIAL_EFFECT":
                continue
            for target in EFFECT_STATES:
                with self.assertRaises(EffectTransitionRefused):
                    assert_transition(state, target)

    def test_partial_effect_only_compensates(self):
        self.assertEqual(ALLOWED_TRANSITIONS["PARTIAL_EFFECT"], frozenset({"COMPENSATED"}))
        self.assertEqual(assert_transition("PARTIAL_EFFECT", "COMPENSATED"),
                         ("PARTIAL_EFFECT", "COMPENSATED"))
        with self.assertRaises(EffectTransitionRefused):
            assert_transition("PARTIAL_EFFECT", "RECONCILED")

    def test_reconciled_is_terminal(self):
        self.assertTrue(is_terminal("RECONCILED"))
        with self.assertRaises(EffectTransitionRefused):
            assert_transition("RECONCILED", "READBACK")


if __name__ == "__main__":
    unittest.main()
