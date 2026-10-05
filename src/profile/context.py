"""W1 execution-context seam - PD-PKG-05 owned contracts.

Source basis (PD-PKG-05): TeamTopology, ExecutionContextProfile, PermissionEnvelopePlan,
PermissionEnvelope, ContextHandoffPacket, CapabilityProjectionProfile, QualificationHandoff.

Law: these are TYPED PROJECTIONS, not memory truth and not runtime parallelism. Provider presence
or tool visibility NEVER increases rights; QualificationHandoff prepares, it does not self-award PASS.
"""
from __future__ import annotations

from dataclasses import dataclass, field

VALID_LANES = ("SERIAL", "BOUNDED_PARALLEL")


@dataclass
class TeamTopology:
    """PD-PKG-05 H1-06 team/delegation. Declaring a topology does NOT start any runtime lane."""
    topology_id: str
    lanes: list = field(default_factory=list)
    join_policy: str = "ALL_MUST_COMPLETE"
    cancel_policy: str = "CANCEL_SIBLINGS"
    adjudication_policy: str = "HGK_DETERMINISTIC"

    def validate(self) -> "TeamTopology":
        if not self.lanes:
            raise ProfileDefect("TeamTopology requires at least one lane")
        for ln in self.lanes:
            if ln.get("mode") not in VALID_LANES:
                raise ProfileDefect(f"lane mode must be one of {VALID_LANES}")
        if not self.adjudication_policy:
            raise ProfileDefect("adjudication_policy is required")
        return self

    @property
    def runtime_parallelism_observed(self) -> bool:
        """Design topology is never evidence of runtime parallelism."""
        return False


@dataclass
class ExecutionContextProfile:
    """Typed projection: provenance + budget + hydration + long-running continuation."""
    profile_id: str
    provenance_refs: list = field(default_factory=list)
    budget: dict = field(default_factory=dict)
    hydration: str = "LAZY"
    continuation: str = "SERIAL_NATIVE"
    is_memory_truth: bool = False


@dataclass
class PermissionEnvelope:
    """Least privilege. Rights come from human/product authority, never from tool/provider presence."""
    envelope_id: str
    granted: list = field(default_factory=list)
    denied: list = field(default_factory=list)
    expires_at: str = ""
    revocable: bool = True

    def effective(self, requested: list, *, tool_presence: list | None = None) -> list:
        tool_presence = tool_presence or []
        for p in requested:
            if p in self.denied:
                raise ProfileDefect(f"permission {p!r} is explicitly denied")
            if p not in self.granted:
                # presence of a tool/provider NEVER grants the right
                raise ProfileDefect(
                    f"permission {p!r} not granted (tool presence {tool_presence!r} does not increase rights)")
        return list(requested)


@dataclass
class ContextHandoffPacket:
    """checkpoint / ACK-NACK / recovery / LKG."""
    handoff_id: str
    checkpoint_ref: str
    lkg_ref: str = ""
    ack: bool = False
    recovery_path: str = ""

    def validate(self) -> "ContextHandoffPacket":
        if not self.checkpoint_ref or not self.recovery_path:
            raise ProfileDefect("ContextHandoffPacket requires checkpoint_ref and recovery_path")
        return self


@dataclass
class CapabilityProjectionProfile:
    profile_id: str
    capability_contract_ref: str
    provider_neutral: bool = True

    def validate(self) -> "CapabilityProjectionProfile":
        if not self.provider_neutral:
            raise ProfileDefect("CapabilityProjectionProfile must stay provider-neutral")
        return self


@dataclass
class QualificationHandoff:
    """PD05 prepares qualification; it never self-awards PASS."""
    handoff_id: str
    subject_sha: str
    evidence_refs: list = field(default_factory=list)
    checker_identity: str = ""

    def award_pass(self):
        raise ProfileDefect("QualificationHandoff prepares; it cannot self-award PASS (SoD)")


class ProfileDefect(Exception):
    code = "PROFILE_DEFECT"
