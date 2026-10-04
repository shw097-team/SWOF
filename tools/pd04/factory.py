"""PD04 construction-packet factory (SWOF W0-003).

RBWI 10.1 fixed compilation spine:
    TaskSpecSeed -> TaskSpec -> WorkOrder -> ONE ECP / evidence edge

RBWI 10.4 regression predicate (enforced here):
    every repo-mutating WorkOrder requires fresh_repocontext_ref, pd04_packet_ref,
    taskspec_ref, ecp_ref, source_requirement_edges, acceptance_edges, evidence_edges.
    Missing any one => FAIL_PD04_ROUTE.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any

REQUIRED_REFS = (
    "fresh_repocontext_ref",
    "pd04_packet_ref",
    "taskspec_ref",
    "ecp_ref",
    "source_requirement_edges",
    "acceptance_edges",
    "evidence_edges",
)


class PD04RouteError(Exception):
    """Raised as FAIL_PD04_ROUTE when a required PD04 ref is missing."""

    code = "FAIL_PD04_ROUTE"

    def __init__(self, workorder_id: str, missing: list[str]):
        self.workorder_id = workorder_id
        self.missing = tuple(missing)
        super().__init__(f"{self.code}: {workorder_id} missing {', '.join(missing)}")


@dataclass
class TaskSpecSeed:
    workorder_id: str
    wave: str
    objective: str
    source_requirement_locators: list = field(default_factory=list)
    dependency_edges: list = field(default_factory=list)
    fresh_repocontext_ref: str | None = None
    wave_basis: str | None = None


@dataclass
class TaskSpec:
    taskspec_id: str
    workorder_id: str
    objective: str
    proposed_bounded_write_set: list
    acceptance_edges: list
    evidence_edges: list
    security_edges: list = field(default_factory=list)
    rollback_edges: list = field(default_factory=list)
    invalidation_edges: list = field(default_factory=list)


@dataclass
class WorkOrderPacket:
    workorder_id: str
    wave: str
    taskspec_id: str
    writer: str
    state: str = "PLANNED_NOT_DISPATCHED"
    execution_binding: Any = None


@dataclass
class ECP:
    """Exactly ONE engineering change proposal per WorkOrder."""
    ecp_id: str
    workorder_id: str
    scope: str
    route: str = "NATIVE"
    reason_code: str = "ROUTE_DEFAULT_NATIVE"


@dataclass
class ConstructionPacket:
    task_spec_seed: TaskSpecSeed
    task_spec: TaskSpec
    workorder: WorkOrderPacket
    ecp: ECP
    fresh_repocontext_ref: str | None = None
    pd04_packet_ref: str | None = None

    def refs(self) -> dict:
        return {
            "fresh_repocontext_ref": self.fresh_repocontext_ref,
            "pd04_packet_ref": self.pd04_packet_ref,
            "taskspec_ref": self.task_spec.taskspec_id,
            "ecp_ref": self.ecp.ecp_id,
            "source_requirement_edges": self.task_spec_seed.source_requirement_locators,
            "acceptance_edges": self.task_spec.acceptance_edges,
            "evidence_edges": self.task_spec.evidence_edges,
        }

    def assert_routable(self) -> None:
        """RBWI 10.4: fail closed with FAIL_PD04_ROUTE if any required ref is absent."""
        r = self.refs()
        missing = [k for k in REQUIRED_REFS if not r.get(k)]
        if missing:
            raise PD04RouteError(self.workorder.workorder_id, missing)

    def to_dict(self) -> dict:
        d = {
            "schema": "PD04-CONSTRUCTION-PACKET/1",
            "workorder_id": self.workorder.workorder_id,
            "wave": self.workorder.wave,
            "task_spec_seed": asdict(self.task_spec_seed),
            "task_spec": asdict(self.task_spec),
            "workorder": asdict(self.workorder),
            "ecp": asdict(self.ecp),
            "execution_binding": None,
        }
        d.update({k: v for k, v in self.refs().items()})
        return d

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)
                              .encode("utf-8")).hexdigest()


def compile_packet(seed: TaskSpecSeed, taskspec: TaskSpec, writer: str = "codex",
                   scope: str = "") -> ConstructionPacket:
    """Compile ONE TaskSpecSeed -> TaskSpec -> WorkOrder -> ONE ECP packet."""
    wo = WorkOrderPacket(workorder_id=seed.workorder_id, wave=seed.wave,
                         taskspec_id=taskspec.taskspec_id, writer=writer)
    ecp = ECP(ecp_id=f"ECP-{seed.workorder_id}", workorder_id=seed.workorder_id, scope=scope)
    packet = ConstructionPacket(
        task_spec_seed=seed, task_spec=taskspec, workorder=wo, ecp=ecp,
        fresh_repocontext_ref=seed.fresh_repocontext_ref,
        pd04_packet_ref=f"PD04::{seed.workorder_id}",
    )
    packet.assert_routable()
    return packet
