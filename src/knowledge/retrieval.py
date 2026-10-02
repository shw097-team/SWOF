"""Four orthogonal query-time retrieval objects. PI-PKG-05 D05-H1-03.

RetrievalPlan says HOW to look; CandidateEnvelope says WHAT a lane returned with lineage;
GroundingResult says WHICH atomic claims are supported by valid witnesses; RetrievalEvaluation
says HOW the system performed. Their states cannot be inferred from each other.

  AVAILABLE source != ELIGIBLE source
  ELIGIBLE source != RETRIEVED candidate
  RETRIEVED candidate != GROUNDED witness
  GROUNDED answer != ACCEPTED package/release
"""
from __future__ import annotations

from dataclasses import dataclass, field


class GroundingDefect(Exception):
    code = "GROUNDING_DEFECT"


class ScopeWidening(Exception):
    """PI-PKG-05 D05-H1-04: new_scope must be a subset of the original authorised scope."""

    code = "SCOPE_WIDENING"


# D05-H1-03 retrieval lifecycle (frozen through EXECUTION_PENDING)
RETRIEVAL_LIFECYCLE = (
    "QUERY_RECEIVED", "CLASSIFIED", "AUTH_SCOPE_RESOLVED", "PLAN_DRAFTED", "PLAN_VALIDATED",
    "CANDIDATE_GENERATION_READY", "EXECUTION_PENDING", "CANDIDATES_RETURNED", "GENERATION_RECHECKED",
    "GROUNDING_PENDING", "GROUNDED", "EVALUATED", "IF05B_READY",
)
GROUNDED_TERMINALS = ("GROUNDED", "PARTIALLY_GROUNDED", "UNGROUNDED", "CONFLICT", "STALE", "REVOKED",
                      "ABSTAINED")


@dataclass
class RetrievalPlan:
    """HOW to look. Never permission or semantic truth."""
    plan_id: str
    query_id: str
    query_class: str
    use_class: str
    authorized_scope: frozenset
    plan_scope: frozenset
    state: str = "PLAN_DRAFTED"
    writer: str = "DOC-05"

    def validate(self) -> "RetrievalPlan":
        if self.state not in RETRIEVAL_LIFECYCLE:
            raise GroundingDefect(f"unknown plan state {self.state}")
        if not self.plan_scope <= self.authorized_scope:
            raise ScopeWidening(
                f"rewrite widened scope: {sorted(self.plan_scope - self.authorized_scope)} "
                f"is outside the original authorized scope")
        self.state = "PLAN_VALIDATED"
        return self


@dataclass
class CandidateEnvelope:
    """WHAT a lane returned, with lineage. A high score never implies eligibility."""
    candidate_id: str
    source_id: str
    generation: int
    score: float
    locator: str
    eligible: bool
    state: str = "RETRIEVED"

    def as_grounding_input(self) -> "CandidateEnvelope":
        if not self.eligible:
            raise GroundingDefect(
                f"candidate {self.candidate_id} is RETRIEVED but not ELIGIBLE; retrieval != eligibility")
        return self


@dataclass
class GroundingResult:
    """WHICH atomic claims are supported by valid witnesses. Never an AcceptanceDecision."""
    result_id: str
    claims: list = field(default_factory=list)
    witnesses: dict = field(default_factory=dict)
    state: str = "GROUNDING_PENDING"

    def ground(self) -> "GroundingResult":
        unsupported = [c for c in self.claims if not self.witnesses.get(c)]
        self.state = "GROUNDED" if not unsupported else "UNGROUNDED"
        return self

    def as_acceptance(self):
        """GROUNDED answer != ACCEPTED package/release. This is deliberately unavailable."""
        raise GroundingDefect(
            "a GroundingResult can never be promoted to an AcceptanceDecision "
            "(GROUNDED answer != ACCEPTED package/release)")


@dataclass
class RetrievalEvaluation:
    """HOW the retrieval/grounding system performed. Never package assurance PASS."""
    eval_id: str
    subject_ref: str
    retrieval_metrics: dict = field(default_factory=dict)
    generation_metrics: dict = field(default_factory=dict)
    state: str = "EVALUATED"

    def as_package_assurance(self):
        raise GroundingDefect(
            "a RetrievalEvaluation is never package assurance PASS (retrieval score != acceptance)")
