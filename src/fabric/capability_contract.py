"""CapabilityContract — the provider-neutral narrow waist (PI-PKG-04 §6.1, §9.1).

This object states WHAT execution capability is required and under what constraints.
It never names a provider: `provider_binding_ref` is optional and late-bound, and
`semantic_writer` is FORBIDDEN_PROVIDER_SIDE.

PI-PKG-04 §9.1 required/optional/unknown policy is enforced here:
  * a missing required field -> CONTRACT_INVALID (never a provider default)
  * unknown fields -> REJECT_UNKNOWN_NORMATIVE_FIELD
  * canonical serialization: UTF-8 + stable key ordering + schema version + content digest,
    and the digest is the subject key for binding/evidence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = "SWOF-CAPABILITY-CONTRACT/1"
SEMANTIC_WRITER = "FORBIDDEN_PROVIDER_SIDE"


class ContractInvalid(Exception):
    """PI-PKG-04 §9.1: a required field is missing. Never filled from a provider default."""

    code = "CONTRACT_INVALID"


class UnknownNormativeField(Exception):
    """PI-PKG-04 §9.1: design parser must REJECT_UNKNOWN_NORMATIVE_FIELD."""

    code = "REJECT_UNKNOWN_NORMATIVE_FIELD"


class AuthorityCapture(Exception):
    """PI-PKG-04 §9.2/§9.4: a provider tried to write semantic meaning."""

    code = "TT-AUTHORITY-CAPTURE"


# PI-PKG-04 §9.1 — required fields (verbatim list; provider_binding_ref is optional/late-bound)
REQUIRED_FIELDS = (
    "contract_id", "semantic_subject_ref", "mission_ref", "taskspec_ref", "ecp_design_ref",
    "capability_id", "capability_version", "input_schema_ref", "output_schema_ref",
    "error_schema_ref", "required_effect_class", "requested_permissions", "denied_permissions",
    "budget", "timeout_policy", "retry_policy", "idempotency_class", "evidence_contract_ref",
    "compatibility_range", "fallback_capability_ref",
)
OPTIONAL_FIELDS = ("provider_binding_ref",)
BUDGET_FIELDS = ("time_ms", "token_or_compute", "money_ceiling", "retry_budget")

# semantic meaning an adapter may NEVER alter (PI-PKG-04 §9.2)
SEMANTIC_MEANING_FIELDS = ("mission_ref", "taskspec_ref", "ecp_design_ref")


@dataclass
class CapabilityContract:
    contract_id: str
    semantic_subject_ref: str
    mission_ref: str
    taskspec_ref: str
    ecp_design_ref: str
    capability_id: str
    capability_version: str
    input_schema_ref: str
    output_schema_ref: str
    error_schema_ref: str
    required_effect_class: str
    requested_permissions: list
    denied_permissions: list
    budget: dict
    timeout_policy: dict
    retry_policy: dict
    idempotency_class: str
    evidence_contract_ref: str
    compatibility_range: str
    fallback_capability_ref: str | None = None
    provider_binding_ref: str | None = None
    owner: str = "ROLE-PROV-001"
    semantic_writer: str = SEMANTIC_WRITER
    design_state: str = "PROPOSED"
    extensions: dict = field(default_factory=dict)

    # ---- validation -------------------------------------------------------
    def validate(self) -> "CapabilityContract":
        missing = [f for f in REQUIRED_FIELDS if getattr(self, f, None) in (None, "", [], {})]
        # fallback_capability_ref is required_when_nonlocal: only enforced by the binder
        if "fallback_capability_ref" in missing:
            missing.remove("fallback_capability_ref")
        if missing:
            raise ContractInvalid(f"{self.__class__.__name__} missing required fields: "
                                  f"{', '.join(sorted(missing))}")
        if self.semantic_writer != SEMANTIC_WRITER:
            raise AuthorityCapture(
                f"semantic_writer must be {SEMANTIC_WRITER}; provider-side semantic writes are forbidden")
        if not isinstance(self.budget, dict) or any(k not in self.budget for k in BUDGET_FIELDS):
            raise ContractInvalid(f"budget must carry {BUDGET_FIELDS}")
        if self.design_state not in ("PROPOSED", "VALIDATED", "SLOT_BOUND", "QUALIFICATION_PLANNED"):
            raise ContractInvalid(f"unknown design_state {self.design_state!r}")
        return self

    @classmethod
    def from_mapping(cls, data: dict, *, parser: str = "design") -> "CapabilityContract":
        known = set(REQUIRED_FIELDS) | set(OPTIONAL_FIELDS) | {
            "owner", "semantic_writer", "design_state", "extensions"}
        unknown = sorted(set(data) - known)
        if unknown:
            if parser == "design":
                raise UnknownNormativeField(f"REJECT_UNKNOWN_NORMATIVE_FIELD: {unknown}")
            # migration parser only: namespaced extension, and it may not overwrite canonical fields
            for k in unknown:
                if not k.startswith("x-"):
                    raise UnknownNormativeField(f"migration extension must be namespaced (x-*): {k}")
            data = dict(data)
            data["extensions"] = {k: data.pop(k) for k in unknown}
        # DEFECT-W1-001: validate the REQUIRED set from the mapping BEFORE constructing the
        # dataclass, so a missing field surfaces as CONTRACT_INVALID and not a TypeError.
        missing = [f for f in REQUIRED_FIELDS if data.get(f) in (None, "", [], {})]
        if "fallback_capability_ref" in missing:
            missing.remove("fallback_capability_ref")  # required_when_nonlocal: binder enforces
        if missing:
            raise ContractInvalid(
                f"CapabilityContract missing required fields: {', '.join(sorted(missing))}")
        obj = cls(**{k: v for k, v in data.items() if k in known})
        obj.validate()
        return obj

    # ---- canonical serialization (PI-PKG-04 §9.1) -------------------------
    # DEFECT-W1-002: binding mutates design_state/provider_binding_ref. The content digest is the
    # contract's SUBJECT KEY, so it must be the stable identity of the SEMANTIC content and must not
    # move when the contract is bound. Binding state is deliberately excluded.
    DIGEST_EXCLUDED = ("design_state", "provider_binding_ref", "extensions")

    def canonical_json(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if k not in self.DIGEST_EXCLUDED}
        payload["schema_version"] = SCHEMA_VERSION
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def content_digest(self) -> str:
        """The digest is the subject key for binding and evidence."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    # ---- state machine (PI-PKG-04 §9.3) -----------------------------------
    def advance(self, to_state: str) -> "CapabilityContract":
        order = ["PROPOSED", "VALIDATED", "SLOT_BOUND", "QUALIFICATION_PLANNED"]
        if to_state not in order:
            raise ContractInvalid(f"unknown target state {to_state!r}")
        cur = order.index(self.design_state)
        if order.index(to_state) != cur + 1:
            raise ContractInvalid(f"illegal transition {self.design_state} -> {to_state}")
        self.design_state = to_state
        return self
