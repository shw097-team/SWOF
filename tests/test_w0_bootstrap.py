"""W0-002 exit tests - stdlib unittest, no third-party runner required."""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W1_SUBSYSTEMS = {'fabric', 'knowledge', 'admission', 'security', 'assurance', 'ops',
                 'product', 'domains', 'research', 'evolution', 'migration'}


class TestW0Bootstrap(unittest.TestCase):
    def _git(self, *args):
        r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
        return r.returncode, r.stdout.strip()

    def test_git_repo_present(self):
        """Hermetic (W0-HERMETIC-001): skip rather than fail when run outside a git worktree."""
        if not (ROOT / ".git").exists():
            self.skipTest("no .git worktree (export/CI checkout) - repository identity is host-bound")
        rc, _ = self._git("rev-parse", "--git-dir")
        self.assertEqual(rc, 0, "W0-002 exit: not a usable git repository")

    def test_on_a_candidate_branch(self):
        """The real invariant is the codex/* candidate-branch convention, NOT one hardcoded name.

        W0-HERMETIC-001: the previous form hardcoded 'codex/swof-w0-construction', so any
        legitimate publication branch failed the suite. It also failed on an export checkout.
        """
        if not (ROOT / ".git").exists():
            self.skipTest("no .git worktree (export/CI checkout)")
        rc, branch = self._git("branch", "--show-current")
        if rc != 0 or not branch:
            self.skipTest("detached HEAD or no branch - branch identity not applicable")
        self.assertTrue(branch.startswith("codex/"),
                        f"durable mutation must run on a codex/* candidate branch, got {branch!r}")

    def test_no_w0_semantic_implementation(self):
        """W0 invariant, wave-scoped correctly: W0 introduces no semantic implementation.

        The original violation path src/swof/ must stay absent, and src/ may only ever contain
        W1+ subsystem packages - never a W0-owned artifact.
        (Repaired by corrective CW-1: the earlier form asserted src/ never exists, which W1-001
        legitimately invalidated by creating src/fabric/.)
        """
        self.assertFalse((ROOT / "src" / "swof").exists(),
                         "src/swof/ was the W0-002-WS-001 violation path and must remain absent")
        src = ROOT / "src"
        if src.exists():
            for child in src.iterdir():
                if child.is_dir():
                    self.assertIn(child.name, W1_SUBSYSTEMS,
                                  f"src/{child.name} is not an admitted W1+ subsystem package")

    def test_workspace_config_declares_non_authority(self):
        cfg = json.loads((ROOT / "config" / "workspace.json").read_text(encoding="utf-8"))
        self.assertFalse(cfg["semantic_authority"], "product root must not claim semantic authority")
        self.assertEqual(cfg["repo_role"], "PRODUCT_ROOT_UNDER_HGK_GOVERNANCE")

    def test_readme_does_not_claim_semantic_authority(self):
        txt = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("never semantic authority", txt)
        for bad in ("is the semantic authority", "authoritative semantic root"):
            self.assertNotIn(bad, txt)


if __name__ == "__main__":
    unittest.main()
