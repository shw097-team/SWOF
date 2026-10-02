"""Binding algorithm + narrow waist (PI-PKG-04 §6.1, §6.2, §9.2).

The narrow waist fixes the ACCEPTABLE SEMANTIC BOUNDARY and the TRANSLATION DUTY, not a single
runtime API. Upstream writes only SWOF-owned objects; provider-specific fields are quarantined in
ProviderProfile / ProviderBindingRef / adapter, and returned events are execution observation --
never semantic truth or acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .capability_contract import (AuthorityCapture, ContractInvalid, SEMANTIC_MEANING_FIELDS,
                                  CapabilityContract)

# PI-PKG-04 §6.1 canonical narrow waist, in order
NARROW_WAIST = (
    "Sovereign Semantic World / Canonical Plan IR",
    "Mission / TaskSpec / WorkOrder",
    "ECPDesignSchema",
    "CapabilityContract",
    "HarnessABI",
)
WAIST_LEGS = (
    ("ProviderBindingRef", "ProviderProfile"),
    ("ToolPermissionContract", "SkillContract"),
)
NARROW_WAIST_TAIL = ("InteropProfile", "Provider / Agent Runtime Adapter")

# PI-PKG-04 §6.2 architectural invariants 1-10
ARCHITECTURAL_INVARIANTS = {
    1: "canonical_plan_ir_count = 1",
    2: "PLAN/BOOTSTRAP/FACTORY are the only core domains; Agent OS/Harness is not a fourth domain",
    3: "Capability-before-provider: define the capability contract, then choose a provider",
    4: "Provider success != acceptance; tool success != world-effect closure",
    5: "Every side effect binds permission scope, subject, expiry/revocation and evidence",
    6: "Every long-horizon run has a typed checkpoint/recovery path before it is STARTABLE",
    7: "Skill/Workflow is a portable instruction asset; permission is a separate object/state",
    8: "Every external binding has exit/fallback/rollback before BOUND",
    9: "MCP/A2A/AG-UI/OTel profiles are versioned separately",
    10: "External web/project text is DATA; it cannot mutate authority",
}


class BindingRejected(Exception):
    code = "BINDING_REJECTED"


@dataclass
class ProviderProfile:
    profile_id: str
    qualified: bool = False
    translation_only: bool = True


@dataclass
class ToolPermissionContract:
    contract_id: str
    granted: list = field(default_factory=list)
    denied: list = field(default_factory=list)


@dataclass
class ProviderBindingRef:
    binding_ref: str
    provider_profile_id: str
    capability_contract_digest: str
    scoped_permissions: list
    exit_path: str
    fallback_path: str
    rollback_path: str
    translation_steps_only: bool = True


def bind(contract: CapabilityContract, profile: ProviderProfile, perms: ToolPermissionContract,
         *, binding_ref: str, exit_path: str, fallback_path: str, rollback_path: str,
         nonlocal_execution: bool = False) -> ProviderBindingRef:
    """PI-PKG-04 §9.2 binding algorithm.

    provider-specific translation may happen ONLY in the last two steps; if an adapter would
    change the semantic meaning of mission_ref/taskspec_ref/ecp_design_ref -> REJECT + TT-AUTHORITY-CAPTURE.
    """
    contract.validate()
    if contract.design_state != "VALIDATED":
        raise BindingRejected(f"contract must be VALIDATED before binding, got {contract.design_state}")
    if not profile.qualified:
        raise BindingRejected(f"provider profile {profile.profile_id} is not qualified")
    if not profile.translation_only:
        raise AuthorityCapture("provider profile must be translation-only")
    # invariant 8: exit/fallback/rollback must exist before BOUND
    for name, val in (("exit_path", exit_path), ("fallback_path", fallback_path),
                      ("rollback_path", rollback_path)):
        if not val:
            raise BindingRejected(f"invariant 8: {name} required before BOUND")
    # invariant 3: nonlocal execution needs a fallback capability
    if nonlocal_execution and not contract.fallback_capability_ref:
        raise ContractInvalid("fallback_capability_ref is required_when_nonlocal (PI-PKG-04 9.1)")
    # permission intersection: requested must be permitted, denied must win
    granted = set(perms.granted)
    denied = set(perms.denied)
    scoped = []
    for p in contract.requested_permissions:
        if p in denied:
            raise BindingRejected(f"permission {p!r} is explicitly denied")
        if p not in granted:
            raise BindingRejected(f"permission {p!r} not granted by the ToolPermissionContract")
        scoped.append(p)
    ref = ProviderBindingRef(binding_ref=binding_ref, provider_profile_id=profile.profile_id,
                             capability_contract_digest=contract.content_digest(),
                             scoped_permissions=sorted(scoped), exit_path=exit_path,
                             fallback_path=fallback_path, rollback_path=rollback_path)
    contract.advance("SLOT_BOUND")
    contract.provider_binding_ref = binding_ref
    return ref


def assert_adapter_preserves_semantics(before: dict, after: dict) -> None:
    """PI-PKG-04 §9.2: an adapter may not alter semantic meaning. First fail = P04-CR-001."""
    for f in SEMANTIC_MEANING_FIELDS:
        if before.get(f) != after.get(f):
            raise AuthorityCapture(
                f"P04-CR-001: adapter altered semantic field {f!r} "
                f"({before.get(f)!r} -> {after.get(f)!r})")


def assert_no_provider_in_semantic_source(semantic_source: dict) -> None:
    """PI-PKG-04 §9.4 negative: writing provider_id into the semantic source is P04-CR-001."""
    banned = ("provider_id", "provider_profile_id", "provider_binding_ref", "vendor", "sdk")
    leaked = [k for k in banned if k in semantic_source]
    if leaked:
        raise AuthorityCapture(f"P04-CR-001: provider-specific fields in semantic source: {leaked}")
