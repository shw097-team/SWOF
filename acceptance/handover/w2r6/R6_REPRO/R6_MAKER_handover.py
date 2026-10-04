#!/usr/bin/env python3
"""Assemble the single-MD external acceptance handover pack for SWOF W2 R6.
Embeds ALL raw evidence inline (per the user's external-acceptance convention).
"""
import os, json, hashlib

EV = r"C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/evidence/R6_EVIDENCE"
HAND = r"C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/evidence/R6_HANDOVER"
OUT = r"C:/Projects/Agent_Workspace/知識庫/實作相關DOC/SWOF/驗收證據/W2R6/SWOF_W2_R6_EXTERNAL_ACCEPTANCE_HANDOVER.md"
SRC = "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
EVC = "6c58c21eee69391ba146e21e27b6d3b7f8f2211c"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def sh(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()

EMBED = [
    ("R6_POLICY_TRUST_ADJUDICATION.json", "json"),
    ("R6_RAW_ADJUDICATION_TRANSCRIPT.log", "text"),
    ("R6_RAW_FOCUSED_PROBES.log", "text"),
    ("R6_FULL_REGRESSION_INDEX.json", "json"),
    ("R6_ROOT_w1_tests.log", "text"), ("R6_ROOT_w1_fabric.log", "text"),
    ("R6_ROOT_w1_knowledge.log", "text"), ("R6_ROOT_w1_admission.log", "text"),
    ("R6_ROOT_w1_profile.log", "text"), ("R6_ROOT_w1_capability.log", "text"),
    ("R6_ROOT_w2_security.log", "text"), ("R6_ROOT_w2_effect.log", "text"),
    ("R6_ROOT_w2_assurance.log", "text"), ("R6_ROOT_w2_observability.log", "text"),
    ("R6_FRESH_CHECKER_REPORT.md", "text"),
    ("R6_FRESH_CHECKER_TRANSCRIPT.log", "text"),
    ("R6_FRESH_CHECKER_FINDINGS.json", "json"),
    ("R6_FRESH_CHECKER_RECEIPT.json", "json"),
    ("R6_W2_NORMATIVE_CLOSURE_PROJECTION.json", "json"),
    ("R6_COMPILER_RECEIPT.json", "json"),
    ("R6_EVIDENCE_MANIFEST.json", "json"),
    ("SWOF_W2_R6_EVIDENCE_RETURN_PACK.json", "json"),
]

def fenced(path, kind):
    txt = open(path, encoding="utf-8", errors="replace").read()
    lang = "json" if kind == "json" else "text"
    return "```" + lang + "\n" + txt + "\n```"

def main():
    L = []
    L.append("# SWOF W2 R6 — External Acceptance Handover (single-MD, full raw embedded)\n")
    L.append("```yaml")
    L.append("repair_id: SWOF-W2-CLOSURE-R6")
    L.append("changeset: NARROW_REPAIR (Branch A)")
    L.append("repo: shw097-team/SWOF")
    L.append("pr: 7")
    L.append(f"source_candidate_sha: {SRC}")
    L.append(f"evidence_commit_sha: {EVC}")
    L.append("parent_source_sha: 02736d3eeb6156e9763f202fbd63fff430e9eeb7")
    L.append("parent_evidence_sha: a6ee9b5ce8b0b0905be4952c32b2ddd747929c25")
    L.append("source_ne_evidence: true")
    L.append("claim_ceiling: READY_FOR_W2_EXTERNAL_RECHALLENGE only")
    L.append("non_claims: [NOT_EXTERNALLY_ACCEPTED, W3_NOT_STARTED, NOT_MERGED, NOT_RELEASED, NOT_PRODUCTION, NO_WORLD_EFFECT]")
    L.append("```\n")
    L.append("## 0. Verification verdicts (maker + independent checker)\n")
    L.append("- Adjudication: **A_BLOCKER_CONFIRMED** (read-only deterministic, frozen PI06 + exact source).")
    L.append("- Product repair: owner-injected `request_resolver` seam; policy-owned fields pinned; fail-closed `DENY_REQUEST_UNRESOLVED` / `DENY_REQUEST_POLICY_MISMATCH`; floor/authority read from trusted request.")
    L.append("- Focused adversarial set `TestR6TrustedRequestBoundary` A1–A13: **13/13 PASS**.")
    L.append("- Regression: **W1=113, W2=783, grand=896** (>=883, +13, no shrink), zero-denominator roots=0, all roots exit 0.")
    L.append("- Fresh independent checker (fresh-context, VERIFY_ONLY, read-only, NOT maker): **product/governance/wave = PASS**, no CONFIRMED_DEFECT.")
    L.append("- Compiler: 5-stage **PROMPT_COMPILE_PASS** (contract sha256 `82cb7049422a8f6d84c04d42a24cc56804c93944d43fe3e02a6800a1b43ef70a`).\n")
    L.append("## A. Raw evidence embedded from the exact evidence commit\n")
    L.append("Each block is byte-identical to the file at `acceptance/evidence/w2r1/" + SRC + "/` in evidence commit `" + EVC + "`.\n")
    for rel, kind in EMBED:
        fp = os.path.join(EV, rel)
        if not os.path.exists(fp):
            L.append(f"### {rel}\n\n_(ABSENT)_\n"); continue
        L.append(f"### {rel}\n")
        L.append(f"- sha256: `{sh(fp)}` · bytes: {os.path.getsize(fp)}\n")
        L.append(fenced(fp, kind)); L.append("")
    L.append("## B. Handover bundle (reproducibility inputs)\n")
    for root, _d, files in os.walk(HAND):
        for f in sorted(files):
            fp = os.path.join(root, f)
            r = os.path.relpath(fp, HAND).replace("\\", "/")
            L.append(f"- `{r}` — sha256 `{sh(fp)}`, {os.path.getsize(fp)} bytes")
    L.append("")
    L.append("## C. Locators\n")
    L.append("- source branch: `wo/swof-w2-closure-r1` @ " + SRC)
    L.append("- evidence branch: `evidence/swof-w2r6-closure-repair` @ tip d67c511 (immutable subject = " + EVC + ")")
    L.append("- main: `acdbfaadd19d12927eb5bd542b09ed230bbc481e` (unchanged)")
    L.append("- PR #7 head: " + SRC + " (open, not merged)")
    L.append("- readset: `SWOF-W2-R6-EXTERNAL-ACCEPTANCE-READSET.json` in the evidence subject")
    L.append("")
    md = "\n".join(L)
    open(OUT, "w", encoding="utf-8").write(md)
    print(json.dumps({"out": OUT, "bytes": len(md.encode()),
                      "sha256": hashlib.sha256(md.encode()).hexdigest(),
                      "embedded": len(EMBED)}, indent=2))

if __name__ == "__main__":
    main()