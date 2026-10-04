#!/usr/bin/env python3
"""Validate and render a thin construction-and-acceptance prompt contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_ID = "CAPC-PROMPT-CONTRACT/1"
ACTIVE = {"ACTIVE_REQUIRED", "ACTIVE_SELECTED"}
DISPOSITIONS = ACTIVE | {
    "STANDBY",
    "OPTIONAL",
    "DEFERRED_SOURCE_BACKED",
    "DONOR_ONLY",
    "NATIVE_SUBSTITUTED",
    "NOT_APPLICABLE_SOURCE_BACKED",
    "PROHIBITED",
}
CHANGESETS = {
    "NEW_IMPLEMENTATION",
    "CONTINUATION",
    "NARROW_REPAIR",
    "UPGRADE",
    "QUALIFICATION_ONLY",
    "EVIDENCE_ONLY",
    "EXTERNAL_ACCEPTANCE_ONLY",
    "PRODUCTION_PROMOTION",
}
LIFECYCLE_STAGES = (
    "identify",
    "pin",
    "install_materialize",
    "configure",
    "discover",
    "bind",
    "route",
    "effective_load",
    "doctor_health",
    "positive_pilot",
    "negative_security",
    "fallback",
    "rollback_uninstall",
    "independent_qualification",
    "certify",
    "enable",
)
NONTERMINAL_EVIDENCE = {
    "FILE_EXISTS",
    "SYMBOL_EXISTS",
    "STATIC_MAPPING_PASS",
    "SHARED_TEST_PASS",
    "MAKER_PROXY_PASS",
    "MAKER_ATTESTED_PASS",
    "SUMMARY_ONLY",
    "DOCUMENTED",
    "DESIGN_READY",
    "DISPOSITION_COMPLETE",
}
INDEPENDENT_TERMINALS = {
    "INDEPENDENT_CASE_PASS",
    "INDEPENDENT_CASE_FAIL",
    "BLOCKED_HITL",
    "BLOCKED_EXTERNAL",
}
CHECKPOINT_FIELDS = {
    "task_id",
    "source_hashes",
    "current_candidate",
    "completed_gates",
    "open_gates",
    "next_work_order",
    "rollback_pointer",
}
CLAIM_LEVEL = {
    "LOCAL": 0,
    "PACKAGE": 1,
    "EXTERNAL_ACCEPTANCE": 2,
    "PRODUCTION": 3,
}
REQUIRED_TOP = {
    "schema",
    "task_id",
    "source_scan",
    "intent",
    "authority",
    "changeset",
    "execution_scope",
    "runtime_readiness",
    "journeys",
    "acceptance",
    "evidence",
    "termination",
    "render_policy",
}


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("contract root must be an object")
    return data


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def withdraw_executable_outputs(out_dir: Path) -> None:
    """Remove only compiler-owned executable outputs after a blocked compile."""
    for name in ("thin-prompt.md", "compiler-receipt.json"):
        path = out_dir / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def error(code: str, message: str, path: str = "") -> dict[str, str]:
    return {"code": code, "message": message, "path": path}


def unique_errors(items: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, str]] = []
    for item in items:
        key = (item["code"], item["path"], item["message"])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda row: (row["code"], row["path"], row["message"]))


def schema_errors(contract: dict[str, Any], schema_path: Path) -> list[dict[str, str]]:
    """Use Draft 2020-12 when available; retain stdlib cross-checks otherwise."""
    try:
        from jsonschema import Draft202012Validator  # type: ignore
    except ImportError:
        return []
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    rows = []
    for issue in sorted(validator.iter_errors(contract), key=lambda e: list(e.absolute_path)):
        pointer = "/" + "/".join(str(x) for x in issue.absolute_path)
        rows.append(error("PL-SCHEMA", issue.message, pointer))
    return rows


def acceptance_subjects(contract: dict[str, Any]) -> set[str]:
    return {
        str(row.get("subject_id", ""))
        for row in contract.get("acceptance", [])
        if isinstance(row, dict)
    }


def readiness_by_capability(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("capability", "")): row
        for row in contract.get("runtime_readiness", [])
        if isinstance(row, dict)
    }


def valid_native_substitution(row: dict[str, Any]) -> bool:
    sub = row.get("native_substitution")
    if not isinstance(sub, dict):
        return False
    required = {
        "equivalence",
        "owner_approval_locator",
        "route_target",
        "positive_test",
        "negative_test",
        "fallback",
        "rollback",
        "independent_evidence",
    }
    if not required.issubset(sub):
        return False
    if not isinstance(sub.get("equivalence"), list) or not sub["equivalence"]:
        return False
    return all(sub.get(key) for key in required - {"equivalence"})


def lint_contract(
    contract: dict[str, Any],
    *,
    use_schema: bool = True,
    schema_path: Path | None = None,
) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if use_schema:
        resolved_schema = schema_path or Path(__file__).resolve().parents[1] / "references" / "prompt-contract.schema.json"
        if resolved_schema.exists():
            errors.extend(schema_errors(contract, resolved_schema))

    missing_top = sorted(REQUIRED_TOP - set(contract))
    unknown_top = sorted(set(contract) - REQUIRED_TOP)
    if missing_top:
        errors.append(error("PL-SCHEMA", f"missing top-level keys: {missing_top}", "/"))
    if unknown_top:
        errors.append(error("PL-SCHEMA", f"unknown top-level keys: {unknown_top}", "/"))
    if contract.get("schema") != SCHEMA_ID:
        errors.append(error("PL-SCHEMA", f"schema must be {SCHEMA_ID}", "/schema"))

    render_policy = contract.get("render_policy", {})
    if render_policy.get("control_corpus_restatement") is True:
        errors.append(error("PL-001", "control corpus restatement is forbidden", "/render_policy/control_corpus_restatement"))
    if render_policy.get("embedded_control_bodies"):
        errors.append(error("PL-001", "embedded control bodies create a second RBWI", "/render_policy/embedded_control_bodies"))

    intent = contract.get("intent", {})
    for field in ("goal", "user_expected_outcome", "user_expected_experience", "claim_ceiling"):
        if not intent.get(field):
            errors.append(error("PL-002", f"missing intent field: {field}", f"/intent/{field}"))
    for field in ("explicit_constraints", "non_goals", "authorized_mutations", "forbidden_mutations"):
        if not isinstance(intent.get(field), list):
            errors.append(error("PL-002", f"intent field must be a list: {field}", f"/intent/{field}"))

    scan = contract.get("source_scan", {})
    required_families = set(scan.get("required_source_families", []))
    reviewed_rows = [row for row in scan.get("reviewed", []) if isinstance(row, dict)]
    reviewed_families = {str(row.get("source_family", "")) for row in reviewed_rows}
    missing_families = set(scan.get("missing", []))
    duplicate_reviewed = len(reviewed_families) != len(reviewed_rows)
    if required_families != reviewed_families or missing_families or duplicate_reviewed:
        errors.append(
            error(
                "PL-003",
                f"source scan incomplete: required={sorted(required_families)} reviewed={sorted(reviewed_families)} missing={sorted(missing_families)} duplicate={duplicate_reviewed}",
                "/source_scan",
            )
        )
    for index, row in enumerate(reviewed_rows):
        if not row.get("locator"):
            errors.append(error("PL-003", "reviewed source lacks locator", f"/source_scan/reviewed/{index}/locator"))
    for index, claim in enumerate(scan.get("normative_claims", [])):
        if not claim.get("locators") or not claim.get("source_ids"):
            errors.append(error("PL-003", "normative claim lacks source and locator", f"/source_scan/normative_claims/{index}"))

    authority = contract.get("authority", {})
    sources = [row for row in authority.get("sources", []) if isinstance(row, dict)]
    for index, row in enumerate(sources):
        if row.get("role") == "NORMATIVE" and not row.get("locator"):
            errors.append(error("PL-003", "normative authority lacks locator", f"/authority/sources/{index}/locator"))
        if row.get("role") == "SUPPORT" and row.get("governs") is True:
            errors.append(error("PL-004", "support source cannot govern normative behavior", f"/authority/sources/{index}/governs"))
    for index, conflict in enumerate(authority.get("conflicts", [])):
        if conflict.get("equal_rank") is True and conflict.get("decision") != "RESOLVED":
            errors.append(error("PL-004", "unresolved equal-rank conflict", f"/authority/conflicts/{index}"))
    if authority.get("missing_sources"):
        errors.append(error("PL-003", "authority has missing required sources", "/authority/missing_sources"))

    changeset = contract.get("changeset", {})
    changeset_class = changeset.get("class")
    if changeset_class not in CHANGESETS:
        errors.append(error("PL-005", f"invalid ChangeSet class: {changeset_class}", "/changeset/class"))

    subjects = acceptance_subjects(contract)
    acceptance_ids = {
        str(row.get("acceptance_id", ""))
        for row in contract.get("acceptance", [])
        if isinstance(row, dict)
    }
    readiness = readiness_by_capability(contract)
    execution_rows = [row for row in contract.get("execution_scope", []) if isinstance(row, dict)]
    for index, row in enumerate(execution_rows):
        cap = str(row.get("capability", ""))
        disposition = row.get("current_execution_disposition")
        selected = any(
            row.get(key) is True
            for key in (
                "current_profile_selected",
                "canonical_flow_referenced",
                "automatic_route_target",
                "user_experience_required",
            )
        )
        if not row.get("source_locators"):
            errors.append(error("PL-003", f"capability {cap} lacks source locator", f"/execution_scope/{index}/source_locators"))
        if disposition not in DISPOSITIONS:
            errors.append(error("PL-006", f"unknown execution disposition for {cap}", f"/execution_scope/{index}/current_execution_disposition"))
        if selected and disposition not in ACTIVE and disposition != "NATIVE_SUBSTITUTED":
            errors.append(error("PL-006", f"Activation Bridge mismatch for {cap}", f"/execution_scope/{index}"))
        if disposition == "NATIVE_SUBSTITUTED" and not valid_native_substitution(row):
            errors.append(error("PL-006", f"invalid native substitution for {cap}", f"/execution_scope/{index}/native_substitution"))
        if disposition in ACTIVE:
            if not row.get("action") or row.get("action") == "NONE":
                errors.append(error("PL-007", f"active capability {cap} lacks closure action", f"/execution_scope/{index}/action"))
            if cap not in subjects:
                errors.append(error("PL-007", f"active capability {cap} lacks acceptance edge", f"/execution_scope/{index}"))
            if row.get("runtime_required_now") is True:
                readiness_row = readiness.get(cap)
                if readiness_row is None:
                    errors.append(error("PL-007", f"active runtime capability {cap} lacks readiness row", f"/execution_scope/{index}"))
                else:
                    if readiness_row.get("required_now") is not True:
                        errors.append(error("PL-007", f"{cap} readiness row is not required now", f"/runtime_readiness/{cap}/required_now"))
                    unknown_acceptance = set(readiness_row.get("acceptance_ids", [])) - acceptance_ids
                    if unknown_acceptance:
                        errors.append(error("PL-007", f"{cap} readiness references unknown acceptance IDs: {sorted(unknown_acceptance)}", f"/runtime_readiness/{cap}/acceptance_ids"))
                    lifecycle = readiness_row.get("lifecycle", {})
                    missing_stages = [stage for stage in LIFECYCLE_STAGES if stage not in lifecycle]
                    if missing_stages:
                        errors.append(error("PL-008", f"{cap} readiness row missing stages: {missing_stages}", f"/runtime_readiness/{cap}/lifecycle"))
                    for stage in ("discover", "bind", "route", "effective_load"):
                        if not lifecycle.get(stage):
                            errors.append(error("PL-008", f"{cap} lacks {stage} state", f"/runtime_readiness/{cap}/lifecycle/{stage}"))
                    if readiness_row.get("current_verdict") != "RUNTIME_READY" and not readiness_row.get("work_required"):
                        errors.append(error("PL-007", f"{cap} has open runtime state without closure work", f"/runtime_readiness/{cap}/work_required"))
        elif row.get("action") in {"INSTALL", "QUALIFY", "ENABLE"}:
            errors.append(error("PL-017", f"unselected capability {cap} requests {row.get('action')}", f"/execution_scope/{index}/action"))
        if row.get("external_method") is True and row.get("control_authority") is True:
            errors.append(error("PL-018", f"external method {cap} cannot become control authority", f"/execution_scope/{index}/control_authority"))

    native_ids = set(authority.get("native_control_plane_ids", []))
    current_control = authority.get("current_control_plane_id")
    if current_control and current_control not in native_ids:
        errors.append(error("PL-018", "current control plane is not declared native", "/authority/current_control_plane_id"))

    for index, journey in enumerate(contract.get("journeys", [])):
        if journey.get("required", True):
            jid = str(journey.get("journey_id", ""))
            if not journey.get("source_expectation_ids") or not journey.get("source_locators"):
                errors.append(error("PL-009", f"journey {jid} lacks source expectation mapping", f"/journeys/{index}"))
            if jid not in subjects:
                errors.append(error("PL-009", f"journey {jid} lacks acceptance edge", f"/journeys/{index}"))
            for capability in journey.get("required_capabilities", []):
                matching = [row for row in execution_rows if row.get("capability") == capability]
                if not matching or matching[0].get("current_execution_disposition") not in ACTIVE | {"NATIVE_SUBSTITUTED"}:
                    errors.append(error("PL-006", f"required journey {jid} depends on inactive capability {capability}", f"/journeys/{index}/required_capabilities"))

    for subject_type, field in (("REQUIREMENT", "active_requirement_ids"), ("DELIVERABLE", "requested_delivery")):
        for subject_id in intent.get(field, []):
            if subject_id not in subjects:
                errors.append(error("PL-009", f"{subject_type.lower()} {subject_id} lacks acceptance edge", f"/intent/{field}"))

    for index, row in enumerate(contract.get("acceptance", [])):
        terminals = set(row.get("terminal_states", []))
        if terminals & NONTERMINAL_EVIDENCE:
            errors.append(error("PL-010", f"nonterminal proxy allowed for {row.get('acceptance_id')}", f"/acceptance/{index}/terminal_states"))
        if row.get("runtime_required") is True:
            if row.get("required_depth") in {"L0_STATIC_EXISTENCE", "L1_SCHEMA_CONTRACT"}:
                errors.append(error("PL-010", f"runtime subject {row.get('subject_id')} has shallow acceptance", f"/acceptance/{index}/required_depth"))
            if not terminals & INDEPENDENT_TERMINALS:
                errors.append(error("PL-010", f"runtime subject {row.get('subject_id')} lacks independent terminal", f"/acceptance/{index}/terminal_states"))
            if row.get("raw_evidence_required") is not True:
                errors.append(error("PL-011", f"runtime subject {row.get('subject_id')} can omit raw evidence", f"/acceptance/{index}/raw_evidence_required"))
            if row.get("independent_checker_required") is not True:
                errors.append(error("PL-012", f"runtime subject {row.get('subject_id')} can omit independent check", f"/acceptance/{index}/independent_checker_required"))

    ceiling = intent.get("claim_ceiling")
    if ceiling not in CLAIM_LEVEL:
        errors.append(error("PL-014", f"invalid claim ceiling: {ceiling}", "/intent/claim_ceiling"))
    for index, row in enumerate(contract.get("evidence", [])):
        if row.get("runtime_pass_allowed") is True and row.get("raw_receipt_required") is not True:
            errors.append(error("PL-011", f"runtime gate {row.get('gate_id')} can omit raw receipt", f"/evidence/{index}"))
        if row.get("producer") and row.get("producer") == row.get("independent_checker"):
            errors.append(error("PL-012", f"maker equals checker for {row.get('gate_id')}", f"/evidence/{index}"))
        binding = row.get("candidate_binding", {})
        if row.get("tracked_subject") is True:
            if not binding.get("head") or not binding.get("package_sha256") or not binding.get("source_hashes"):
                errors.append(error("PL-013", f"tracked gate {row.get('gate_id')} lacks exact candidate binding", f"/evidence/{index}/candidate_binding"))
        claim = row.get("claim_level", "LOCAL")
        if ceiling in CLAIM_LEVEL and (claim not in CLAIM_LEVEL or CLAIM_LEVEL[claim] > CLAIM_LEVEL[ceiling]):
            errors.append(error("PL-014", f"gate claim {claim} exceeds ceiling {ceiling}", f"/evidence/{index}/claim_level"))

    bounded_classes = {
        "CONTINUATION",
        "NARROW_REPAIR",
        "UPGRADE",
        "QUALIFICATION_ONLY",
        "EVIDENCE_ONLY",
        "EXTERNAL_ACCEPTANCE_ONLY",
    }
    if changeset_class in bounded_classes:
        if not changeset.get("affected_domains") or not changeset.get("must_not_reopen"):
            errors.append(error("PL-015", f"{changeset_class} lacks affected scope or do-not-reopen boundary", "/changeset"))
        if changeset.get("baseline_required") is not True:
            errors.append(error("PL-015", f"{changeset_class} must declare a baseline", "/changeset/baseline_required"))
    if changeset.get("reuse_prior_pass") is True and changeset.get("baseline_verified") is not True:
        errors.append(error("PL-015", "prior PASS cannot be reused before baseline verification", "/changeset/baseline_verified"))
    if changeset_class == "EVIDENCE_ONLY" and changeset.get("product_mutation_allowed") is True:
        errors.append(error("PL-015", "evidence-only ChangeSet allows product mutation", "/changeset/product_mutation_allowed"))

    termination = contract.get("termination", {})
    terminals = set(termination.get("terminal_states", []))
    pauses = set(termination.get("non_terminal_pause", []))
    if terminals & pauses or {"ITERATION_BUDGET_PAUSE", "SESSION_BOUNDARY"} & terminals:
        errors.append(error("PL-016", "pause is incorrectly terminal", "/termination"))
    checkpoint_fields = set(termination.get("checkpoint_fields", []))
    if termination.get("checkpoint_required") is not True or not CHECKPOINT_FIELDS.issubset(checkpoint_fields):
        errors.append(error("PL-016", "checkpoint contract is incomplete", "/termination/checkpoint_fields"))

    return unique_errors(errors)


def status_payload(errors: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "verdict": "PROMPT_COMPILE_BLOCKED" if errors else "PROMPT_COMPILE_PASS",
        "error_count": len(errors),
        "errors": errors,
    }


def bullets(items: Iterable[str]) -> str:
    rows = [f"- {item}" for item in items if item]
    return "\n".join(rows) if rows else "- none"


def render_prompt(contract: dict[str, Any]) -> str:
    intent = contract["intent"]
    changeset = contract["changeset"]
    authority = contract["authority"]
    active = [row for row in contract["execution_scope"] if row["current_execution_disposition"] in ACTIVE]
    inactive = [row for row in contract["execution_scope"] if row["current_execution_disposition"] not in ACTIVE]
    readiness = readiness_by_capability(contract)

    source_lines = [
        f"{row['rank']} {row['path']} {row['locator']} role={row['role']}"
        for row in authority["sources"]
    ]
    active_lines = [
        f"{row['capability']}: {row['current_execution_disposition']}; action={row['action']}; runtime_required={str(row['runtime_required_now']).lower()}"
        for row in active
    ]
    inactive_lines = [
        f"{row['capability']}: {row['current_execution_disposition']}; action={row['action']}"
        for row in inactive
    ]
    readiness_lines = []
    for row in active:
        if row.get("runtime_required_now") is True:
            runtime = readiness.get(row["capability"], {})
            readiness_lines.append(
                f"{row['capability']}: verdict={runtime.get('current_verdict')}; work={'; '.join(runtime.get('work_required', [])) or 'none'}"
            )
    journey_lines = [
        f"{row['journey_id']}: {row['user_goal']} → {row['expected_visible_result']}"
        for row in contract["journeys"]
        if row.get("required", True)
    ]
    acceptance_lines = [
        f"{row['acceptance_id']} subject={row['subject_id']} depth={row['required_depth']}"
        for row in contract["acceptance"]
    ]
    baseline = (
        f"required={str(changeset['baseline_required']).lower()}; "
        f"verified={str(changeset['baseline_verified']).lower()}; "
        f"reuse_prior_pass={str(changeset['reuse_prior_pass']).lower()}"
    )

    prompt = f"""# EXECUTABLE THIN CONSTRUCTION & ACCEPTANCE PROMPT

## 0. Machine Header
task_id: {contract['task_id']}
contract_schema: {contract['schema']}
compiler_state: PROMPT_COMPILE_PASS

## 1. Mission / ChangeSet
Mission: {intent['goal']}
Expected outcome: {intent['user_expected_outcome']}
ChangeSet: {changeset['class']}
Affected domains: {', '.join(changeset['affected_domains']) or 'none'}

## 2. Authority / Files-first order
Read and hash the exact sources below in order. Use their owned controls directly; do not restate or replace them.
{bullets(source_lines)}
Equal-rank conflict => quarantine, TT, and stop the affected work.

## 3. Intent / Non-goals / Claim ceiling
Expected experience: {intent['user_expected_experience']}
Constraints:
{bullets(intent['explicit_constraints'])}
Non-goals:
{bullets(intent['non_goals'])}
Authorized mutations:
{bullets(intent['authorized_mutations'])}
Forbidden mutations:
{bullets(intent['forbidden_mutations'])}
Claim ceiling: {intent['claim_ceiling']}

## 4. Active / Deferred / Forbidden scope
Active:
{bullets(active_lines)}
Non-active:
{bullets(inactive_lines)}
Do not install, enable, or qualify a non-active capability.

## 5. Baseline / Reuse / Do-not-redo
Baseline: {baseline}
Do not reopen:
{bullets(changeset['must_not_reopen'])}
Verify source and candidate bindings before reuse. A tracked mutation invalidates the affected seal.

## 6. Implementation and qualification gates
Use Manifest → owner WP/RBWI → TaskSpec/WorkOrder → active AGENTS/SKILLS → Harness/Loop.
Runtime closure:
{bullets(readiness_lines)}
Required user journeys:
{bullets(journey_lines)}
Acceptance predicates:
{bullets(acceptance_lines)}
Proxy, static, maker, shared, file-presence, or summary evidence cannot close runtime behavior.

## 7. Failure / HITL / Repair / Resume
Use the smallest affected repair, focused tests, affected regression, independent recheck, and a new checkpoint.
Require HITL for: {', '.join(intent['allowed_hitl']) or 'none'}.
No silent fallback. Use only a certified explicit substitute; otherwise return BLOCKED_EXTERNAL or BLOCKED_HITL.

## 8. Evidence / Independent acceptance / Candidate binding
Return case-specific raw receipts, command or probe, stdout/stderr/exit, producer, independent checker, source hashes, candidate head/package hash, invalidation, rollback, and residue readback.
Maker output is an evidence candidate, not a final verdict.

## 9. Termination / Final output
Terminal states: {', '.join(contract['termination']['terminal_states'])}.
Nonterminal pauses: {', '.join(contract['termination']['non_terminal_pause'])}.
Iteration or session pause requires a checkpoint and is not completion.
Return no claim above {intent['claim_ceiling']}.
"""
    return prompt.rstrip() + "\n"


def normalized_words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_\-/]+", text.lower())


def shingles(text: str, size: int = 8) -> set[tuple[str, ...]]:
    words = normalized_words(text)
    if len(words) < size:
        return {tuple(words)} if words else set()
    return {tuple(words[index : index + size]) for index in range(len(words) - size + 1)}


def duplication_ratio(prompt_text: str, source_text: str, size: int = 8) -> float:
    prompt_shingles = shingles(prompt_text, size)
    if not prompt_shingles:
        return 0.0
    return len(prompt_shingles & shingles(source_text, size)) / len(prompt_shingles)


def filter_errors(errors: list[dict[str, str]], codes: set[str]) -> list[dict[str, str]]:
    return [row for row in errors if row["code"] in codes or row["code"] in {"PL-SCHEMA", "PL-003", "PL-004", "PL-005"}]


def compile_contract(contract_path: Path, out_dir: Path) -> tuple[int, dict[str, Any]]:
    contract = load_json(contract_path)
    errors = lint_contract(contract)
    report = status_payload(errors)
    report.update(
        {
            "task_id": contract.get("task_id"),
            "contract_sha256": digest_file(contract_path),
            "claim_ceiling": contract.get("intent", {}).get("claim_ceiling"),
        }
    )
    atomic_write(out_dir / "compiler-report.json", json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    if errors:
        withdraw_executable_outputs(out_dir)
        return 2, report

    prompt = render_prompt(contract)
    max_chars = int(contract.get("render_policy", {}).get("max_prompt_chars", 16000))
    if len(prompt) > max_chars:
        too_long = [error("PL-001", f"rendered prompt has {len(prompt)} chars; maximum is {max_chars}", "/render_policy/max_prompt_chars")]
        report = status_payload(too_long)
        report.update({"task_id": contract.get("task_id"), "contract_sha256": digest_file(contract_path)})
        atomic_write(out_dir / "compiler-report.json", json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        withdraw_executable_outputs(out_dir)
        return 2, report

    prompt_path = out_dir / "thin-prompt.md"
    atomic_write(prompt_path, prompt.encode("utf-8"))
    receipt = {
        "schema": "CAPC-COMPILER-RECEIPT/1",
        "task_id": contract["task_id"],
        "verdict": "PROMPT_COMPILE_PASS",
        "contract_sha256": digest_file(contract_path),
        "prompt_sha256": digest_file(prompt_path),
        "compiler_sha256": digest_file(Path(__file__)),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_claim": "NOT_EVALUATED",
        "independent_claim": "NOT_EVALUATED",
        "production_claim": "NOT_CLAIMED",
    }
    atomic_write(out_dir / "compiler-receipt.json", json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return 0, report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("lint", "activation", "acceptance", "render", "compile", "hash"):
        child = sub.add_parser(name)
        child.add_argument("contract", type=Path)
        if name == "render":
            child.add_argument("--out", type=Path)
        if name == "compile":
            child.add_argument("--out-dir", type=Path, required=True)

    duplicate = sub.add_parser("duplication")
    duplicate.add_argument("prompt", type=Path)
    duplicate.add_argument("--source", action="append", type=Path, required=True)
    duplicate.add_argument("--threshold", type=float, default=0.25)
    duplicate.add_argument("--shingle-size", type=int, default=8)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "hash":
        print(digest_file(args.contract))
        return 0
    if args.command == "duplication":
        prompt_text = args.prompt.read_text(encoding="utf-8")
        ratios = [
            {
                "source": str(path),
                "ratio": round(duplication_ratio(prompt_text, path.read_text(encoding="utf-8"), args.shingle_size), 6),
            }
            for path in args.source
        ]
        failures = [row for row in ratios if row["ratio"] > args.threshold]
        payload = {
            "verdict": "PROMPT_COMPILE_BLOCKED" if failures else "PROMPT_COMPILE_PASS",
            "rule": "PL-001",
            "threshold": args.threshold,
            "results": ratios,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2 if failures else 0
    if args.command == "compile":
        code, report = compile_contract(args.contract, args.out_dir)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return code

    contract = load_json(args.contract)
    errors = lint_contract(contract)
    if args.command == "activation":
        errors = filter_errors(errors, {"PL-006", "PL-007", "PL-008", "PL-017", "PL-018"})
    elif args.command == "acceptance":
        errors = filter_errors(errors, {"PL-009", "PL-010", "PL-011", "PL-012", "PL-013", "PL-014", "PL-015", "PL-016"})
    payload = status_payload(errors)
    if args.command == "render" and not errors:
        prompt = render_prompt(contract)
        if args.out:
            atomic_write(args.out, prompt.encode("utf-8"))
        else:
            print(prompt, end="")
        return 0
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
