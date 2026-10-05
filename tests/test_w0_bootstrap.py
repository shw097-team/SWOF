"""W0-002 exit tests - stdlib unittest, no third-party runner required."""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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

    def test_on_an_authoritative_candidate_branch(self):
        """Follow the RBWI policy - do NOT redefine it.

        SWOF_HGK_ACA_RBWI.md 12.4: durable repo mutation runs on a branch matching `wo/*` or
        `repair/*`. W1-EXT-004: an earlier form of this test asserted `codex/*` as normative, i.e.
        derived repository code redefining upper-layer publication policy. That is forbidden; the
        repository follows the Runbook's branch rule and never authors it.
        """
        if not (ROOT / ".git").exists():
            self.skipTest("no .git worktree (export/CI checkout)")
        rc, branch = self._git("branch", "--show-current")
        if rc != 0 or not branch:
            self.skipTest("detached HEAD or no branch - branch identity not applicable")
        self.assertTrue(branch.startswith(("wo/", "repair/")),
                        f"RBWI 12.4 requires wo/* or repair/* for durable mutation, got {branch!r}")

    def test_repository_does_not_author_branch_policy(self):
        """Negative fixture (Gate C): the repo must not declare any of its own branch patterns normative."""
        offenders = []
        self_path = Path(__file__).resolve()
        for p in ROOT.rglob("*.py"):
            if ".git" in p.parts:
                continue
            # FIX-3: do not scan this file - it necessarily contains the detection literals below.
            if p.resolve() == self_path:
                continue
            text = p.read_text(encoding="utf-8")
            for bad in ('startswith("codex/")', "startswith('codex/')", "codex/* candidate branch"):
                if bad in text:
                    offenders.append((str(p.relative_to(ROOT)), bad))
        self.assertEqual(offenders, [],
                         f"repository code must not assert a self-authored branch policy: {offenders}")

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
                    # FIX-2: no hardcoded subsystem-name list (it broke when W1 added profile and
                    # capability). Structural invariant instead: every src/<subsystem> must be a
                    # properly-formed package owning its own test root.
                    self.assertTrue((child / "__init__.py").exists(),
                                    f"src/{child.name} is not a package (missing __init__.py)")
                    self.assertTrue((child / "tests").is_dir(),
                                    f"src/{child.name} owns no test root under src/{child.name}/tests")

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
