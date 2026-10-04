#!/usr/bin/env python3
"""R6 evidence manifest + return pack generator.
Run AFTER all artifacts (incl. fresh checker outputs) land in EVIDENCE.
Computes path/kind/sha256/bytes/producer for every artifact; emits
R6_EVIDENCE_MANIFEST.json and SWOF_W2_R6_EVIDENCE_RETURN_PACK.json.
No placeholder hashes; non-self-referential publication state.
"""
import os, json, hashlib, datetime, sys

EV = sys.argv[1] if len(sys.argv) > 1 else r"C:/Projects/Agent_Workspace/HG-KSEOS/var/swof-construction-002-w2-repair-001/evidence/R6_EVIDENCE"
SOURCE_SHA = "94e4c15e1040a159d0eb6ac3ef4089b421e60bf9"
PARENT_EVIDENCE = "a6ee9b5ce8b0b0905be4952c32b2ddd747929c25"

KIND = {
    "R6_POLICY_TRUST_ADJUDICATION.json": ("adjudication", "summary", "hermes-maker"),
    "R6_RAW_ADJUDICATION_TRANSCRIPT.log": ("raw_transcript", "raw", "hermes-maker"),
    "R6_RAW_FOCUSED_PROBES.log": ("raw_probes", "raw", "hermes-maker"),
    "R6_FULL_REGRESSION_INDEX.json": ("regression_index", "summary", "hermes-maker"),
    "R6_FRESH_CHECKER_TRANSCRIPT.log": ("checker_transcript", "raw", "hermes-checker"),
    "R6_FRESH_CHECKER_FINDINGS.json": ("checker_findings", "summary", "hermes-checker"),
    "R6_FRESH_CHECKER_RECEIPT.json": ("checker_receipt", "summary", "hermes-checker"),
    "R6_W2_NORMATIVE_CLOSURE_PROJECTION.json": ("hgk_closure_projection", "summary", "hermes-maker"),
    "R6_COMPILER_RECEIPT.json": ("compiler_receipt", "summary", "compiler"),
    "R6_COMPILED_THIN_PROMPT.md": ("compiled_prompt", "raw", "compiler"),
    "R6_EVIDENCE_MANIFEST.json": ("manifest", "summary", "hermes-maker"),
    "SWOF_W2_R6_EVIDENCE_RETURN_PACK.json": ("return_pack", "summary", "hermes-packer"),
    "SWOF_W2_R6_FINAL_EVIDENCE_DOSSIER.md": ("dossier", "summary", "hermes-maker"),
}

def sha_bytes(p):
    b = open(p, "rb").read()
    return hashlib.sha256(b).hexdigest(), len(b)

def main():
    items = []
    for root, _dirs, files in os.walk(EV):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, EV).replace("\\", "/")
            kind, rawsum, producer = KIND.get(f, ("artifact", "raw", "hermes"))
            h, n = sha_bytes(full)
            items.append({"relative_path": rel, "kind": kind, "sha256": h, "bytes": n,
                          "producer": producer, "raw_vs_summary": rawsum,
                          "source_subject_sha": SOURCE_SHA})
    items.sort(key=lambda x: x["relative_path"])
    manifest = {
        "schema": "SWOF-W2-R6-EVIDENCE-MANIFEST/1",
        "repair_id": "SWOF-W2-CLOSURE-R6",
        "source_subject_sha": SOURCE_SHA,
        "parent_evidence_sha": PARENT_EVIDENCE,
        "item_count": len(items),
        "items": items,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    mj = json.dumps(manifest, ensure_ascii=False, indent=2)
    open(os.path.join(EV, "R6_EVIDENCE_MANIFEST.json"), "w", encoding="utf-8").write(mj)
    mh = hashlib.sha256(mj.encode()).hexdigest()

    # return pack: real item sha/bytes, non-self-referential publication state
    def item(rel):
        fp = os.path.join(EV, rel)
        if not os.path.exists(fp):
            return {"path": rel, "status": "ABSENT"}
        h, n = sha_bytes(fp)
        return {"path": rel, "sha256": h, "bytes": n}
    rp = {
        "schema": "SWOF_W2_R6_EVIDENCE_RETURN_PACK/1",
        "repair_id": "SWOF-W2-CLOSURE-R6",
        "source_candidate_sha": SOURCE_SHA,
        "parent_evidence_sha": PARENT_EVIDENCE,
        "evidence_commit_sha": "PREPUBLICATION / assigned by publication receipt",
        "artifacts": [
            item("R6_POLICY_TRUST_ADJUDICATION.json"),
            item("R6_RAW_ADJUDICATION_TRANSCRIPT.log"),
            item("R6_RAW_FOCUSED_PROBES.log"),
            item("R6_FULL_REGRESSION_INDEX.json"),
            item("R6_FRESH_CHECKER_TRANSCRIPT.log"),
            item("R6_FRESH_CHECKER_FINDINGS.json"),
            item("R6_FRESH_CHECKER_RECEIPT.json"),
            item("R6_W2_NORMATIVE_CLOSURE_PROJECTION.json"),
            item("R6_COMPILER_RECEIPT.json"),
            item("R6_COMPILED_THIN_PROMPT.md"),
            item("R6_EVIDENCE_MANIFEST.json"),
            item("SWOF_W2_R6_FINAL_EVIDENCE_DOSSIER.md"),
        ],
        "manifest_sha256": mh,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    open(os.path.join(EV, "SWOF_W2_R6_EVIDENCE_RETURN_PACK.json"), "w", encoding="utf-8").write(
        json.dumps(rp, ensure_ascii=False, indent=2))
    print(json.dumps({"items": len(items), "manifest_sha256": mh,
                      "return_pack_artifacts": len(rp["artifacts"])}, indent=2))

if __name__ == "__main__":
    main()