"""Dependency identity, pin verification and licence admission.

WHY: a dependency resolved by name and version alone can be swapped for a different artifact
(typosquat, registry takeover), and a build that never checks a hash cannot tell the difference.
This module binds a dependency to a sha256 and a licence, treats a missing hash, an unpinned
declaration and an unknown licence as typed failures, and never reaches the network - it judges
only REGISTERED metadata. It admits nothing beyond the evidence supplied to it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

AUDIT_SCHEMA = "SWOF-SUPPLY-CHAIN-AUDIT/1"

# The known licence vocabulary. A licence outside this set is NOT allowed: unknown is not
# permissive, because "we could not tell" must never admit a dependency.
ALLOWED_LICENSES = frozenset({
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "PSF-2.0",
    "CC0-1.0", "Unlicense", "0BSD", "MPL-2.0",
})


class SupplyChainIdentityMismatch(Exception):
    """The artifact hash is missing or does not match the pinned identity."""

    code = "ERR_SUPPLY_CHAIN_IDENTITY_MISMATCH"


class UnpinnedDependency(Exception):
    """A dependency was declared without a pin."""

    code = "ERR_UNPINNED_DEPENDENCY"


class LicenseNotAllowed(Exception):
    """A dependency has no declared licence, or one outside the allowed set."""

    code = "ERR_LICENSE_NOT_ALLOWED"


@dataclass(frozen=True)
class DependencyIdentity:
    """A registered dependency. `pinned`, `sha256` and `license` are the admission inputs."""

    name: str
    version: str
    sha256: str | None
    license: str | None
    security_metadata: dict = field(default_factory=dict)
    pinned: bool = False


def _dep_valid(dep):
    return isinstance(dep, DependencyIdentity) and bool(dep.name)


def verify_pin(dep, *, actual_sha256) -> dict:
    """Raise unless the dependency is pinned and its hash matches the observed artifact."""
    if not _dep_valid(dep):
        raise UnpinnedDependency("UNKNOWN_DEPENDENCY_FAIL_CLOSED")
    if not dep.pinned:
        raise UnpinnedDependency("%s is not pinned" % dep.name)
    if not dep.sha256 or not isinstance(dep.sha256, str):
        raise SupplyChainIdentityMismatch("%s has no pinned sha256" % dep.name)
    if not isinstance(actual_sha256, str) or not actual_sha256:
        raise SupplyChainIdentityMismatch("%s actual hash is missing" % dep.name)
    if actual_sha256.lower() != dep.sha256.lower():
        raise SupplyChainIdentityMismatch(
            "%s hash mismatch: pinned %s != actual %s" % (dep.name, dep.sha256, actual_sha256))
    return {
        "name": dep.name,
        "version": dep.version,
        "sha256": dep.sha256,
        "verified": True,
        "pinned": True,
    }


def assert_license_allowed(dep, *, allowed_licenses) -> None:
    """Raise unless the declared licence is present and inside the allowed set."""
    if not _dep_valid(dep):
        raise LicenseNotAllowed("UNKNOWN_DEPENDENCY_FAIL_CLOSED")
    allowed = allowed_licenses if allowed_licenses is not None else ALLOWED_LICENSES
    if not isinstance(allowed, (frozenset, set, tuple, list)):
        raise LicenseNotAllowed("UNKNOWN_LICENSE_POLICY_FAIL_CLOSED")
    if not dep.license or not isinstance(dep.license, str):
        raise LicenseNotAllowed("%s has no declared licence" % dep.name)
    if dep.license not in allowed:
        raise LicenseNotAllowed(
            "%s licence %r is not allowed" % (dep.name, dep.license))


def assert_no_unpinned(deps) -> None:
    """Raise on the first unpinned dependency; an empty universe is trivially admissible."""
    if deps is None:
        raise UnpinnedDependency("UNKNOWN_DEPENDENCY_SET_FAIL_CLOSED")
    for dep in deps:
        if not isinstance(dep, DependencyIdentity) or not dep.pinned:
            name = getattr(dep, "name", repr(dep))
            raise UnpinnedDependency("%s is not pinned" % name)


def audit(deps, *, actual_hashes=None) -> dict:
    """Audit registered dependencies; `clean` only when every one is admitted."""
    hashes = actual_hashes or {}
    entries = []
    failures = []
    for dep in deps or ():
        entry = {
            "name": getattr(dep, "name", None),
            "version": getattr(dep, "version", None),
            "pinned": bool(getattr(dep, "pinned", False)),
        }
        try:
            assert_no_unpinned((dep,))
            verify_pin(dep, actual_sha256=hashes.get(getattr(dep, "name", None)))
            assert_license_allowed(dep, allowed_licenses=ALLOWED_LICENSES)
            entry["admitted"] = True
        except (UnpinnedDependency, SupplyChainIdentityMismatch, LicenseNotAllowed) as exc:
            entry["admitted"] = False
            entry["failure"] = exc.code
            failures.append({"name": entry["name"], "code": exc.code, "detail": str(exc)})
        entries.append(entry)
    return {
        "schema": AUDIT_SCHEMA,
        "dependencies": entries,
        "clean": not failures,
        "failures": failures,
    }
