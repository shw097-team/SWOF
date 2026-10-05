"""Separation of duties: the producer may not be the checker, and the checker may not write.

Two rules, both enforced rather than asserted:

    the identity that produced the candidate must not be the identity that checks it
    the checker may NOT write the product, its evaluator, the WorkOrder or the contract

`ReadOnlyChecker.write_product` ALWAYS raises `CheckerWriteRefused`; there is no override and
no flag to relax it. `write_evidence` is the only write a checker may perform, and only inside
the declared evidence root - anything else is a `CheckerWriteRefused`. Every read and every
refused write is recorded in the receipt, so the enforcement is demonstrable from the
evidence trail rather than taken on trust.
"""
from __future__ import annotations

import posixpath


class SoDViolation(Exception):
    """Producer and checker are not separated."""

    code = "ERR_SOD_VIOLATION"

    def __init__(self, message, reason_code="SOD_VIOLATION"):
        super().__init__(message)
        self.reason_code = reason_code


class CheckerWriteRefused(Exception):
    """A read-only checker attempted a write it may not perform."""

    code = "ERR_CHECKER_WRITE_REFUSED"

    def __init__(self, message, reason_code="CHECKER_WRITE_REFUSED"):
        super().__init__(message)
        self.reason_code = reason_code


def assert_separated(producer_id, checker_id, *, independent=True):
    """Return a SoD receipt, or raise SoDViolation when the identities are not separated."""
    producer = "" if producer_id is None else str(producer_id)
    checker = "" if checker_id is None else str(checker_id)
    if not producer or not checker:
        raise SoDViolation(
            "producer_id and checker_id must both be non-empty (producer=%r, checker=%r)"
            % (producer, checker), "SOD_EMPTY_IDENTITY")
    if producer == checker:
        raise SoDViolation(
            "producer and checker are the same identity %r (maker-as-checker)"
            % producer, "SOD_SAME_IDENTITY")
    return {
        "schema": "SWOF-SOD-RECEIPT/1",
        "producer": producer,
        "checker": checker,
        "separated": True,
        "independent": bool(independent),
    }


def _normalize(path):
    return posixpath.normpath(str(path).replace("\\", "/"))


def _within(root, path):
    if not root:
        return False
    root_n = _normalize(root).rstrip("/")
    path_n = _normalize(path)
    return path_n == root_n or path_n.startswith(root_n + "/")


class ReadOnlyChecker:
    """A checker that may read the frozen candidate but may never write the product."""

    def __init__(self, checker_id, *, allowed_evidence_root=""):
        if not checker_id:
            raise SoDViolation("checker_id must be non-empty", "SOD_EMPTY_IDENTITY")
        self._checker_id = checker_id
        self._allowed_evidence_root = allowed_evidence_root or ""
        self._reads = []
        self._refused_writes = []
        self._allowed_writes = []

    @property
    def identity(self):
        return self._checker_id

    def read(self, path):
        self._reads.append(_normalize(path))
        return None

    def write_product(self, path, content):
        self._refused_writes.append({
            "path": _normalize(path),
            "target": "PRODUCT",
            "reason_code": "CHECKER_MAY_NOT_WRITE_PRODUCT",
        })
        raise CheckerWriteRefused(
            "checker %r may not write the product at %r; a checker may not repair the "
            "candidate, its evaluator logic, the WorkOrder or the evidence contract"
            % (self._checker_id, path), "CHECKER_MAY_NOT_WRITE_PRODUCT")

    def write_evidence(self, path, content):
        normalized = _normalize(path)
        if not _within(self._allowed_evidence_root, normalized):
            self._refused_writes.append({
                "path": normalized,
                "target": "EVIDENCE",
                "reason_code": "EVIDENCE_OUTSIDE_ALLOWED_ROOT",
            })
            raise CheckerWriteRefused(
                "checker %r may only write evidence inside %r, refused %r"
                % (self._checker_id, self._allowed_evidence_root, path),
                "EVIDENCE_OUTSIDE_ALLOWED_ROOT")
        self._allowed_writes.append(normalized)
        return {
            "schema": "SWOF-SOD-EVIDENCE-WRITE/1",
            "checker": self._checker_id,
            "path": normalized,
            "allowed": True,
        }

    def record(self):
        return {
            "schema": "SWOF-SOD-CHECKER-RECEIPT/1",
            "checker": self._checker_id,
            "allowed_evidence_root": self._allowed_evidence_root,
            "reads": tuple(self._reads),
            "allowed_writes": tuple(self._allowed_writes),
            "refused_writes": tuple(self._refused_writes),
        }