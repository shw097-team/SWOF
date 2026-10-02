"""CW-2 structural guard: no test may sit after the `if __name__ == "__main__"` guard.

DEFECT-W1-004 was a RECURRENCE of the dead-test pattern: regression tests appended after
`unittest.main()` are never collected, yet the suite still reports OK. This guard makes that
failure mode impossible to ship silently.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_files():
    for p in sorted(ROOT.rglob("test_*.py")):
        if ".git" in p.parts:
            continue
        yield p


class TestTestHygiene(unittest.TestCase):
    def test_no_tests_after_main_guard(self):
        offenders = []
        for p in test_files():
            text = p.read_text(encoding="utf-8")
            m = re.search(r'^if __name__ == ["\']__main__["\']:', text, re.M)
            if not m:
                continue
            tail = text[m.start():]
            if re.search(r"^\s*def test_", tail, re.M):
                offenders.append(str(p.relative_to(ROOT)))
        self.assertEqual(offenders, [],
                         f"test methods defined after the __main__ guard are never collected: {offenders}")

    def test_every_test_file_defines_at_least_one_test(self):
        empty = []
        seen_any = False
        for p in test_files():
            text = p.read_text(encoding="utf-8")
            if re.search(r"^\s*def test_", text, re.M):
                seen_any = True
            elif "__init__" not in p.name:
                empty.append(str(p.relative_to(ROOT)))
        self.assertTrue(seen_any)
        self.assertEqual([e for e in empty if not e.endswith("__init__.py")], [],
                         f"test files with no test methods: {empty}")


if __name__ == "__main__":
    unittest.main()
