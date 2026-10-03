"""Source trust facets + eligibility. PI-PKG-05 Source Trust Facet Algebra.

Rights, provenance, freshness and revocation are ORTHOGONAL facets. Conflating any two
(for example rewriting a REVOKE as a freshness STALE) is a defect: first fail
ORTHOGONAL_TRUST_FACETS.

Law: AVAILABLE source != ELIGIBLE source, and a DELETED/REVOKED generation MUST NOT be
resurrected from index/cache/embedding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TrustDefect(Exception):
    code = "TRUST_DEFECT"


class OrthogonalFacetViolation(Exception):
    """Rights/revocation rewritten as a sibling facet (PI-PKG-05 18.1 'revoked-as-stale')."""

    code = "ORTHOGONAL_TRUST_FACETS"


class ResurrectionRefused(Exception):
    code = "RESURRECTION_REFUSED"


class Rights(Enum):
    GRANTED = "GRANTED"
    DENIED = "DENIED"


class Freshness(Enum):
    CURRENT = "CURRENT"
    STALE = "STALE"


class Revocation(Enum):
    LIVE = "LIVE"
    REVOKED = "REVOKED"
    DELETED = "DELETED"


class Provenance(Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class SourceValidityVector:
    """Four orthogonal facets. A high score on one never substitutes for another."""
    rights: Rights
    freshness: Freshness
    revocation: Revocation
    provenance: Provenance = Provenance.VERIFIED
    generation: int = 1
    origin: str = ""
    purpose: str = ""


@dataclass
class EligibilityDecision:
    eligible: bool
    reason: str


def evaluate_eligibility(v: SourceValidityVector, *, use_class: str, required_purpose: str) -> EligibilityDecision:
    """AVAILABLE != ELIGIBLE. Every facet must independently pass."""
    if v.revocation in (Revocation.REVOKED, Revocation.DELETED):
        return EligibilityDecision(False, f"revocation={v.revocation.value}")
    if v.rights is Rights.DENIED:
        return EligibilityDecision(False, "rights=DENIED")
    if v.freshness is Freshness.STALE:
        return EligibilityDecision(False, "freshness=STALE")
    if v.provenance is Provenance.UNVERIFIED:
        return EligibilityDecision(False, "provenance=UNVERIFIED")
    if required_purpose and v.purpose and v.purpose != required_purpose:
        # PI-PKG-05 18.1 'purpose laundering': an exact purpose/use/operation tuple is required.
        return EligibilityDecision(False, f"purpose mismatch: {v.purpose!r} != {required_purpose!r}")
    return EligibilityDecision(True, "all facets pass")


def refuse_collapse(v: SourceValidityVector, *, claimed_freshness: Freshness) -> SourceValidityVector:
    """Detect 'revoked-as-stale': a revoked source must never be reported as merely stale."""
    if v.revocation is Revocation.REVOKED and claimed_freshness is Freshness.STALE and v.freshness is not Freshness.STALE:
        raise OrthogonalFacetViolation(
            "revoked-as-stale: revocation and freshness are orthogonal; a revoke cannot be rewritten as staleness")
    return v


class SourceFabric:
    """Local-first source fabric with revocation epochs and no-resurrection enforcement."""

    def __init__(self) -> None:
        self._current: dict[str, SourceValidityVector] = {}
        self._epoch: dict[str, int] = {}
        self._tombstones: dict[tuple[str, int], str] = {}
        self._index_cache: set[tuple[str, int]] = set()

    def put(self, source_id: str, v: SourceValidityVector) -> None:
        self._current[source_id] = v
        self._epoch[source_id] = v.generation

    def revoke(self, source_id: str, reason: str = "revoked") -> None:
        v = self._current[source_id]
        self._current[source_id] = SourceValidityVector(
            rights=v.rights, freshness=v.freshness, revocation=Revocation.REVOKED,
            provenance=v.provenance, generation=v.generation, origin=v.origin, purpose=v.purpose)
        self._epoch[source_id] = v.generation + 1
        self._tombstones[(source_id, v.generation)] = reason

    def index(self, source_id: str, generation: int) -> None:
        """Indexing caches a (source, generation) pair; revocation invalidates it."""
        if (source_id, generation) in self._tombstones:
            raise ResurrectionRefused(
                f"indexing a tombstoned generation is refused: {source_id}@{generation}")
        self._index_cache.add((source_id, generation))

    def retrieve(self, source_id: str, generation: int) -> SourceValidityVector:
        """A revoked/deleted generation cannot be resurrected from the index/cache/embedding."""
        if (source_id, generation) in self._tombstones:
            raise ResurrectionRefused(
                f"{source_id}@{generation} is tombstoned and must not be resurrected from index/cache/embedding")
        cur = self._current.get(source_id)
        if cur is None:
            raise TrustDefect(f"unknown source {source_id}")
        if generation != cur.generation:
            raise TrustDefect(
                f"generation mismatch: requested {generation}, current {cur.generation} (stale-as-current refused)")
        return cur
