#!/usr/bin/env python3
"""R6 deterministic raw execution-log generator.

Reproduces the R4-era raw_test_logs format EXACTLY (header comment block +
unittest dots), for every W1/W2 root, against the EXACT new R6 source SHA.
Usage (from the SWOF worktree root, on the repaired branch):
    python <this>.py --repo C:/.../SWOF --out C:/.../evidence/R6_EVIDENCE
Writes:
    R6_ROOT_<name>.log        (per root, header + stdout)
    R6_FULL_REGRESSION_INDEX.json
    R6_RAW_ADJUDICATION_TRANSCRIPT.log     (if --adjudication provided, else deferred)
    R6_RAW_FOCUSED_PROBES.log
"""
import argparse, json, os, subprocess, sys, time, hashlib, datetime

def now_z():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def git(cwd, *args):
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True).stdout.strip()

def header_lines(cmd, cwd, head, branch, py, phase, started, dur, ec):
    return [("# command : " + cmd),
            ("# cwd     : " + cwd),
            ("# git HEAD: " + head),
            ("# branch  : " + branch),
            ("# python  : " + py),
            ("# phase   : " + phase),
            ("# started : " + started),
            ("# duration: " + dur),
            ("# exit_code: " + str(ec)),
            "------------------------------------------------------------------------------"]

def run_root(cwd, cmd, head, branch, py, phase, outdir, name):
    started = now_z()
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    dur = f"{time.time()-t0:.3f}s"
    header = "\n".join(header_lines(" ".join(cmd), cwd, head, branch, py, phase, started, dur, proc.returncode)) + "\n"
    body = (proc.stdout + "\n" + proc.stderr)
    body = body.replace("\r", "")
    log = header + body
    path = os.path.join(outdir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(log)
    return {"name": name, "command": " ".join(cmd), "exit_code": proc.returncode,
            "started": started, "duration": dur, "sha256": hashlib.sha256(log.encode()).hexdigest(),
            "bytes": len(log.encode())}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--phase", default="w2_candidate_w2r6")
    a = ap.parse_args()
    repo = a.repo
    os.makedirs(a.out, exist_ok=True)
    head = git(repo, "rev-parse", "HEAD")
    branch = git(repo, "branch", "--show-current")
    py = sys.executable
    gen = os.path.join(os.path.dirname(sys.executable), "python.exe")
    results = []
    roots = [
        ("w1_tests", [gen, "-m", "unittest", "discover", "-s", "tests", "-t", "."]),
        ("w1_fabric", [gen, "-m", "unittest", "discover", "-s", "src/fabric/tests", "-t", "src/fabric/tests"]),
        ("w1_knowledge", [gen, "-m", "unittest", "discover", "-s", "src/knowledge/tests", "-t", "src/knowledge/tests"]),
        ("w1_admission", [gen, "-m", "unittest", "discover", "-s", "src/admission/tests", "-t", "src/admission/tests"]),
        ("w1_profile", [gen, "-m", "unittest", "discover", "-s", "src/profile/tests", "-t", "src/profile/tests"]),
        ("w1_capability", [gen, "-m", "unittest", "discover", "-s", "src/capability/tests", "-t", "src/capability/tests"]),
        ("w2_security", [gen, "-m", "unittest", "discover", "-s", "src/security/tests", "-t", "src/security/tests"]),
        ("w2_effect", [gen, "-m", "unittest", "discover", "-s", "src/effect/tests", "-t", "src/effect/tests"]),
        ("w2_assurance", [gen, "-m", "unittest", "discover", "-s", "src/assurance/tests", "-t", "src/assurance/tests"]),
        ("w2_observability", [gen, "-m", "unittest", "discover", "-s", "src/observability/tests", "-t", "src/observability/tests"]),
    ]
    for name, cmd in roots:
        r = run_root(repo, cmd, head, branch, py, a.phase, a.out, f"R6_ROOT_{name}.log")
        results.append(r)
        print(f"[{name}] exit={r['exit_code']} bytes={r['bytes']}")
    index = {
        "schema": "SWOF-W2-R6-FULL-REGRESSION-INDEX/1",
        "phase": a.phase,
        "source_sha": head,
        "generated_at": now_z(),
        "roots": results,
        "summary": {
            "exit_zero_all": all(r["exit_code"] == 0 for r in results),
            "root_count": len(results),
            "zero_denominator_roots": sum(1 for r in results if "passed, 0" in open(os.path.join(a.out, r["name"]), encoding="utf-8").read() and "0 errors" in open(os.path.join(a.out, r["name"]), encoding="utf-8").read()),
        },
    }
    # compute collected pass totals from each log's unittest summary line
    totals = {"w1": {"tests":0,"fabric":0,"knowledge":0,"admission":0,"profile":0,"capability":0},
              "w2": {"security":0,"effect":0,"assurance":0,"observability":0}}
    for r in results:
        txt = open(os.path.join(a.out, r["name"]), encoding="utf-8").read()
        import re
        m = re.search(r"Ran (\d+) tests?", txt)
        n = int(m.group(1)) if m else 0
        key = r["name"].split("R6_ROOT_")[1].replace(".log", "")
        bucket = "w1" if key.startswith("w1_") else "w2"
        seg = key.split("_", 1)[1]
        totals[bucket][seg] = n
    index["denominator"] = {
        "w1_total": sum(totals["w1"].values()),
        "w2_total": sum(totals["w2"].values()),
        "grand_total": sum(totals["w1"].values())+sum(totals["w2"].values()),
        "by_root_w1": totals["w1"], "by_root_w2": totals["w2"],
    }
    index["index_sha256"] = hashlib.sha256(json.dumps(index, sort_keys=True).encode()).hexdigest()
    with open(os.path.join(a.out, "R6_FULL_REGRESSION_INDEX.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    print(json.dumps({"index_sha256": index["index_sha256"], "denominator": index["denominator"]}, indent=2))

if __name__ == "__main__":
    main()