"""Search-Before-Build technology admission ladder. PI-PKG-05 H1-05 / 19.

Ordered dispositions, strongest first:
  REUSE > WRAP > TRANSLATE > ADAPT > COMPOSE > BUILD_MINIMUM > BUILD_NEW_EXCEPTION

Law:
  * Popularity is not qualification.
  * BUILD_MINIMUM requires a documented material gap.
  * BUILD_NEW_EXCEPTION requires evidence that ALL earlier dispositions fail materially.
  * selected != installed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

LADDER = ("REUSE", "WRAP", "TRANSLATE", "ADAPT", "COMPOSE", "BUILD_MINIMUM", "BUILD_NEW_EXCEPTION")
# dispositions that carry an external/canonical technology rather than building our own
EXTERNAL_DISPOSITIONS = ("REUSE", "WRAP", "TRANSLATE", "ADAPT", "COMPOSE")
BUILD_DISPOSITIONS = ("BUILD_MINIMUM", "BUILD_NEW_EXCEPTION")


class AdmissionDefect(Exception):
    code = "ADMISSION_DEFECT"


class PopularityNotQualification(Exception):
    code = "POPULARITY_IS_NOT_QUALIFICATION"


class DowngradeRefused(Exception):
    code = "ANTI_DOWNGRADE_REFUSED"


class SelectedIsNotInstalled(Exception):
    code = "SELECTED_IS_NOT_INSTALLED"


@dataclass
class CandidateDisposition:
    disposition: str
    materially_fails: bool = False
    evidence_ref: str = ""
    documented_material_gap: str = ""


def choose_disposition(candidates: list[CandidateDisposition]) -> CandidateDisposition:
    """Pick the STRONGEST disposition that does not materially fail.

    BUILD_NEW_EXCEPTION is only reachable when every earlier disposition materially fails
    with evidence.
    """
    for c in sorted(candidates, key=lambda c: LADDER.index(c.disposition)):
        if not c.materially_fails:
            if c.disposition == "BUILD_MINIMUM" and not c.documented_material_gap:
                raise AdmissionDefect("BUILD_MINIMUM requires a documented material gap")
            return c
        if c.disposition in BUILD_DISPOSITIONS:
            break
    raise AdmissionDefect(
        "BUILD_NEW_EXCEPTION requires evidence that all earlier dispositions fail materially; none satisfied")


def assert_build_new_exception_allowed(candidates: list[CandidateDisposition]) -> None:
    """DEFECT-W1-003-001: enforce the BUILD_NEW_EXCEPTION precondition as a HARD gate.

    PI-PKG-05 19: 'BUILD_NEW_EXCEPTION requires evidence that all earlier dispositions fail
    materially.' Requesting it while any earlier disposition survives must FAIL CLOSED.
    """
    survivors = [c.disposition for c in candidates
                 if c.disposition in EXTERNAL_DISPOSITIONS + ("BUILD_MINIMUM",) and not c.materially_fails]
    if survivors:
        raise AdmissionDefect(
            f"BUILD_NEW_EXCEPTION refused: earlier dispositions still material: {survivors}")


def assert_anti_downgrade(technology: str, prior: str, proposed: str) -> None:
    """PI-PKG-05 19.1: a fixed selection must not be silently downgraded."""
    if LADDER.index(proposed) > LADDER.index(prior):
        raise DowngradeRefused(
            f"anti-downgrade: {technology} was {prior} and cannot be silently weakened to {proposed}")


def screen_popularity(*, popularity_signal: str, qualification_evidence: str) -> None:
    """Popularity/heat is never qualification (PI-PKG-05 19)."""
    if not qualification_evidence:
        raise PopularityNotQualification(
            f"popularity signal {popularity_signal!r} is not qualification; qualification evidence is required")


@dataclass
class TechnologyRow:
    """A D02-TECH-ADOPTION-LEDGER row, reduced to its decision-bearing fields."""
    tech_id: str
    canonical_identity: str
    disposition: str
    pin: str = "TEMP_CLOSED_PREDEV_EXACT_PIN"
    license: str = ""
    selected: bool = False
    installed: bool = False
    qualified: bool = False
    provider_off: str = ""
    uninstall_exit: str = ""
    rollback: str = ""
    drift_trigger: str = ""
    active: bool = False
    rejected_for_primary_slot: bool = False


class TechnologyAdmissionRegister:
    def __init__(self) -> None:
        self._rows: dict[str, TechnologyRow] = {}

    def register(self, row: TechnologyRow) -> None:
        self._rows[row.tech_id] = row

    def get(self, tech_id: str) -> TechnologyRow:
        if tech_id not in self._rows:
            raise AdmissionDefect(f"unknown technology {tech_id}")
        return self._rows[tech_id]

    def activate(self, tech_id: str) -> TechnologyRow:
        """selected != installed != qualified != active."""
        r = self.get(tech_id)
        if r.rejected_for_primary_slot:
            raise AdmissionDefect(f"{tech_id} is REJECTED_FOR_PRIMARY_POLICY_SLOT and cannot be activated")
        if not r.selected:
            raise SelectedIsNotInstalled(f"{tech_id} is not selected; activation requires selection first")
        if not r.installed:
            raise SelectedIsNotInstalled(f"{tech_id} is selected but NOT installed (selected != installed)")
        if not r.qualified:
            raise AdmissionDefect(f"{tech_id} is installed but not qualified")
        if not (r.provider_off and r.uninstall_exit and r.rollback and r.drift_trigger):
            raise AdmissionDefect(
                f"{tech_id} lacks provider-off/uninstall-exit/rollback/drift-trigger; cannot become ACTIVE")
        r.active = True
        return r

    def is_active(self, tech_id: str) -> bool:
        return self.get(tech_id).active
