"""W0-002 exit tests - stdlib unittest, no third-party runner required."""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestW0Bootstrap(unittest.TestCase):
    def test_git_repo_present(self):
        self.assertTrue((ROOT / ".git").exists(), "W0-002 exit: not a git repository")

    def test_candidate_branch_is_unique(self):
        out = subprocess.run(["git", "-C", str(ROOT), "branch", "--show-current"],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "codex/swof-w0-construction", f"unexpected branch {out!r}")

    def test_no_src_package_in_w0(self):
        """Negative: src/ is granted to W1+ only; W0 must not contain semantic implementation."""
        self.assertFalse((ROOT / "src").exists(),
                         "W0-002 write-set does not grant src/ (defect W0-002-WS-001)")

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
