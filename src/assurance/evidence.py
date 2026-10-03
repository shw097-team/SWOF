"""Evidence: raw-proof-bound, subject-bound, environment-bound linkage.

An evidence item is a claim that a specific RAW artifact exists, hashes to a specific value,
belongs to the plan subject, was produced by the named producer, and was checked by a
checker that is not the producer. Every one of those is a separate rejection class with its
own typed `reason_code`, because each is a distinct way that evidence lies:

    a summary boolean is not evidence          -> FORGED_SUMMARY
    a plausible file with the wrong hash       -> HASH_MISMATCH
    a pre-mutation object sold as final        -> DIRECT_FINAL_CLAIM_ON_PRE_MUTATION
    a moving branch tip sold as an immutable   -> BRANCH_TIP_SUBSTITUTION
    right bytes, wrong subject                 -> WRONG_SUBJECT
    stale / foreign / self-referential         -> STALE / FOREIGN / SELF_REFERENTIAL
    the maker checking its own work            -> CHECKER_EQUALS_PRODUCER

`validate_plan` keeps the per-linkage-mode counters SEPARATE: one mixed counter both over-
and under-reports, so a direct-final defect and a transitive defect must not share a bucket.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

LINKAGE_MODES = ("DIRECT_FINAL_SUBJECT", "TRANSITIVE_PRE_MUTATION_LINEAGE",
                 "COMPILER_CONTRACT_BOUND", "WORKORDER_CHECKPOINT")

REASONS = ("STALE", "FOREIGN", "WRONG_SUBJECT", "SELF_REFERENTIAL", "FORGED_SUMMARY",
           "DIRECT_FINAL_CLAIM_ON_PRE_MUTATION", "BRANCH_TIP_SUBSTITUTION", "HASH_MISMATCH",
           "RAW_PROOF_MISSING", "CHECKER_EQUALS_PRODUCER")

IDENTITY_FIELDS = ("subject_sha", "oracle_id", "environment", "security_config")


class EvidenceRejected(Exception):
    """A specific evidence rejection class. `.reason_code` is one of REASONS."""

    code = "ERR_EVIDENCE_REJECTED"

    def __init__(self, message, reason_code, item_id=""):
        super().__init__(message)
        if reason_code not in REASONS:
            raise ValueError("reason_code %r is not in REASONS" % (reason_code,))
        self.reason_code = reason_code
        self.item_id = item_id


@dataclass(frozen=True)
class EvidenceItem:
    item_id: str
    kind: str
    subject_id: str
    subject_version: str
    sha256: str
    environment: str
    action: str
    checker_id: str
    producer_id: str
    raw_path: str
    linkage_mode: str
    is_pre_mutation: bool = False
    content: bytes = None
    declared_subject_id: str = None
    is_branch_tip: bool = False
    is_summary_only: bool = False
    stale: bool = False


@dataclass(frozen=True)
class EvidencePlan:
    plan_id: str
    subject_id: str
    subject_sha: str
    oracle_id: str
    required: tuple
    checker_id: str
    producer_id: str


def _field(obj, name, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _required_entries(plan):
    entries = _field(plan, "required", ()) or ()
    out = []
    for entry in entries:
        if isinstance(entry, dict):
            out.append((entry.get("kind"), entry.get("linkage_mode"), entry.get("environment")))
        else:
            seq = tuple(entry)
            out.append((seq[0], seq[1], seq[2]))
    return tuple(out)


def _planned_for_kind(plan, kind):
    for entry in _required_entries(plan):
        if entry[0] == kind:
            return entry
    return None


def _pack_marker(plan):
    marker = _field(plan, "pack_path", None) or _field(plan, "pack_root", None)
    if marker:
        return str(marker).replace("\\", "/").strip("/")
    plan_id = _field(plan, "plan_id", None)
    return str(plan_id) if plan_id else None


def _resolve_raw(item, resolver):
    raw_path = _field(item, "raw_path", None)
    resolved = None
    if raw_path and resolver is not None:
        if callable(resolver):
            resolved = resolver(raw_path)
        elif hasattr(resolver, "get"):
            resolved = resolver.get(raw_path)
    if resolved is None:
        resolved = _field(item, "content", None)
    return resolved


def _raw_bytes_as_bytes(resolved):
    if resolved is None:
        return None
    if isinstance(resolved, bytes):
        return resolved
    if isinstance(resolved, str):
        return resolved.encode("utf-8")
    if isinstance(resolved, bytearray):
        return bytes(resolved)
    return None


def _reject(item, reason_code, message):
    raise EvidenceRejected(message, reason_code, str(_field(item, "item_id", "")))


def validate_item(item, *, plan, resolver=None):
    """Validate one evidence item against the plan, or raise the exact EvidenceRejected."""
    item_id = str(_field(item, "item_id", "")) or "<unknown>"
    kind = _field(item, "kind", None)
    raw_path = _field(item, "raw_path", None)
    is_summary_only = bool(_field(item, "is_summary_only", False))
    resolved = _raw_bytes_as_bytes(_resolve_raw(item, resolver))
    declared_sha = _field(item, "sha256", None)

    # 1. A summary boolean is not evidence.
    if is_summary_only and (not raw_path or resolved is None):
        _reject(item, "FORGED_SUMMARY",
                "item %s is summary-only with no resolvable raw artifact: a summary "
                "boolean is not evidence" % item_id)

    # 2. Raw proof must exist for every non-summary item.
    if resolved is None:
        _reject(item, "RAW_PROOF_MISSING",
                "item %s has no raw artifact (raw_path=%r) to bind the shipped hash"
                % (item_id, raw_path))

    # 3. Hash integrity: the declared sha256 must match the resolved raw bytes.
    actual_sha = hashlib.sha256(resolved).hexdigest()
    if not declared_sha or declared_sha != actual_sha:
        _reject(item, "HASH_MISMATCH",
                "item %s declares sha256 %r but the raw artifact hashes to %s"
                % (item_id, declared_sha, actual_sha))

    # 4. Subject binding: hash integrity proves transport, not meaning.
    plan_subject = _field(plan, "subject_id", None)
    if _field(item, "subject_id", None) != plan_subject:
        _reject(item, "WRONG_SUBJECT",
                "item %s subject_id %r != plan subject %r"
                % (item_id, _field(item, "subject_id", None), plan_subject))
    declared_subject = _field(item, "declared_subject_id", None)
    if declared_subject is not None and declared_subject != _field(item, "subject_id", None):
        _reject(item, "WRONG_SUBJECT",
                "item %s declares subject %r but is bound to %r: the bytes are right, the "
                "meaning is not" % (item_id, declared_subject, _field(item, "subject_id", None)))

    # 5. Self-referential evidence: the artifact names the pack that contains it.
    marker = _pack_marker(plan)
    if marker and raw_path:
        normalized = str(raw_path).replace("\\", "/")
        if marker in normalized:
            _reject(item, "SELF_REFERENTIAL",
                    "item %s raw_path %r names the plan pack %r that contains it: the "
                    "evidence is self-referential" % (item_id, raw_path, marker))

    linkage_mode = _field(item, "linkage_mode", None)

    # 6. A pre-mutation artifact may not be sold as direct-final.
    if bool(_field(item, "is_pre_mutation", False)) and linkage_mode == "DIRECT_FINAL_SUBJECT":
        _reject(item, "DIRECT_FINAL_CLAIM_ON_PRE_MUTATION",
                "item %s is pre-mutation but claims DIRECT_FINAL_SUBJECT; it must declare "
                "TRANSITIVE_PRE_MUTATION_LINEAGE" % item_id)

    # 7. A moving branch tip may not substitute for an immutable SHA.
    requires_immutable = bool(_field(plan, "subject_sha", None))
    if bool(_field(item, "is_branch_tip", False)) and requires_immutable:
        _reject(item, "BRANCH_TIP_SUBSTITUTION",
                "item %s is a branch tip; the plan requires the immutable subject SHA"
                % item_id)

    # 8. Staleness.
    if bool(_field(item, "stale", False)):
        _reject(item, "STALE",
                "item %s is stale evidence against the current subject" % item_id)

    # 9. Foreign environment/action: must be the planned linkage and environment.
    planned = _planned_for_kind(plan, kind)
    if planned is not None:
        _, planned_linkage, planned_env = planned
        if planned_env is not None and _field(item, "environment", None) != planned_env:
            _reject(item, "FOREIGN",
                    "item %s environment %r is not the planned environment %r"
                    % (item_id, _field(item, "environment", None), planned_env))
        if planned_linkage is not None and linkage_mode != planned_linkage:
            _reject(item, "FOREIGN",
                    "item %s linkage_mode %r is not the planned linkage_mode %r"
                    % (item_id, linkage_mode, planned_linkage))

    # 10. Separation of duties at the item level.
    checker_id = _field(item, "checker_id", None)
    producer_id = _field(item, "producer_id", None)
    if checker_id and producer_id and checker_id == producer_id:
        _reject(item, "CHECKER_EQUALS_PRODUCER",
                "item %s was produced and checked by %r (maker-as-checker)"
                % (item_id, checker_id))

    return {
        "schema": "SWOF-EVIDENCE-ITEM-VERDICT/1",
        "item_id": item_id,
        "kind": kind,
        "linkage_mode": linkage_mode,
        "accepted": True,
        "reason_code": "ACCEPTED",
    }


def validate_plan(plan, items, *, resolver=None):
    """Validate a whole evidence plan; never passes on an empty item list."""
    items = list(items or ())
    rejected = []
    accepted = []

    for item in items:
        try:
            verdict = validate_item(item, plan=plan, resolver=resolver)
            accepted.append((item, verdict))
        except EvidenceRejected as exc:
            rejected.append({
                "item_id": exc.item_id,
                "kind": _field(item, "kind", None),
                "linkage_mode": _field(item, "linkage_mode", None),
                "reason_code": exc.reason_code,
                "detail": str(exc),
            })

    linkage_modes = {mode: 0 for mode in LINKAGE_MODES}
    for item in items:
        mode = _field(item, "linkage_mode", None)
        if mode in linkage_modes:
            linkage_modes[mode] += 1

    required_entries = _required_entries(plan)
    required_present = 0
    for kind, linkage_mode, environment in required_entries:
        for item, _ in accepted:
            if (_field(item, "kind", None) == kind
                    and _field(item, "linkage_mode", None) == linkage_mode
                    and (environment is None
                         or _field(item, "environment", None) == environment)):
                required_present += 1
                break

    invalid_direct = sum(1 for r in rejected if r["linkage_mode"] == "DIRECT_FINAL_SUBJECT")
    invalid_transitive = sum(
        1 for r in rejected if r["linkage_mode"] == "TRANSITIVE_PRE_MUTATION_LINEAGE")

    passed = bool(items) and not rejected and required_present == len(required_entries)
    return {
        "schema": "SWOF-EVIDENCE-PLAN-VERDICT/1",
        "passed": passed,
        "checked": len(items),
        "rejected": rejected,
        "linkage_modes": linkage_modes,
        "required_present": required_present,
        "invalid_direct_link_count": invalid_direct,
        "invalid_transitive_link_count": invalid_transitive,
    }


def invalidate(plan, *, changed_identity, gates):
    """Return the invalidation cone: gates whose evidence a changed identity rejects."""
    changed = dict(changed_identity or {})
    affected = []
    for gate in sorted(gates or (), key=lambda g: str(_field(g, "gate_id", ""))):
        reasons = []
        if "subject_sha" in changed:
            bound = _field(gate, "subject_sha", None)
            if bound is None or bound != changed["subject_sha"]:
                reasons.append("SUBJECT_SHA_CHANGED")
        if "oracle_id" in changed:
            bound = _field(gate, "oracle_id", None)
            if bound is None or bound == changed["oracle_id"]:
                reasons.append("ORACLE_ID_CHANGED")
        if "environment" in changed:
            bound = _field(gate, "environment", None)
            if bound is None or bound == changed["environment"]:
                reasons.append("ENVIRONMENT_CHANGED")
        if "security_config" in changed or changed.get("security_relevant"):
            reasons.append("SECURITY_CONFIG_CHANGED")
        if reasons:
            affected.append({
                "gate_id": str(_field(gate, "gate_id", "")),
                "invalidated": True,
                "reason_codes": reasons,
            })
    return affected