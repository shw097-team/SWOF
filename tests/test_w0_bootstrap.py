"""W0-002 exit tests: the repository skeleton must be deterministic and empty of product semantics."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_git_repo_present():
    assert (ROOT / ".git").exists(), "W0-002 exit: not a git repository"


def test_candidate_branch_is_unique():
    out = subprocess.run(["git", "-C", str(ROOT), "branch", "--show-current"],
                         capture_output=True, text=True).stdout.strip()
    assert out == "codex/swof-w0-construction", f"unexpected branch {out!r}"


def test_package_imports():
    sys.path.insert(0, str(ROOT / "src"))
    import swof
    assert swof.__version__ == "0.0.0"


def test_no_semantic_authority_claim_in_root():
    """Negative: the product root must not claim semantic authority (PI-PKG-00 2.4 truth separation)."""
    txt = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert "semantic authority" in txt
    for bad in ("is the semantic authority", "authoritative semantic root"):
        assert bad not in txt
