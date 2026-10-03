"""Effect/evidence correlation: bind evidence to the exact effect it is allowed to speak about.

WHY: evidence that is true of subject A must never be counted for effect on subject B, and
evidence from effect X must never be counted for effect Y. Correlation is a four-part identity
(effect, subject, intent digest, environment); this module derives it deterministically and
refuses to bind evidence whose subject or correlation id does not match. Refusal is typed, and
there is no path here that turns a mismatch into a pass.
"""
from __future__ import annotations

import hashlib

CORRELATION_DOMAIN = "swof.effect.correlation.v1"


class WrongSubjectEvidence(Exception):
    """Evidence describes a different subject than the effect record."""

    code = "ERR_WRONG_SUBJECT_EVIDENCE"


class CorrelationMismatch(Exception):
    """Evidence carries a correlation id that is not this effect's identity."""

    code = "ERR_CORRELATION_MISMATCH"


def _part(value, name) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string, got %r" % (name, value))
    return value


def correlation_id(effect_id, subject_id, intent_digest, environment) -> str:
    """Deterministic sha256 hex over all four inputs (length-prefixed, so it is unambiguous)."""
    parts = [
        _part(effect_id, "effect_id"),
        _part(subject_id, "subject_id"),
        _part(intent_digest, "intent_digest"),
        _part(environment, "environment"),
    ]
    material = CORRELATION_DOMAIN + "".join(
        "%d:%s|" % (len(part), part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def expected_correlation_id(record) -> str:
    """The correlation identity a record must carry: its own, or the derived one."""
    if getattr(record, "correlation_id", ""):
        return record.correlation_id
    return correlation_id(record.effect_id, record.subject_id, record.intent_digest,
                          record.environment)


def _evidence_field(evidence, name):
    if isinstance(evidence, dict):
        return evidence.get(name)
    return getattr(evidence, name, None)


def bind_evidence(record, evidence_ref, *, evidence_subject_id,
                  evidence_correlation_id) -> dict:
    """Bind evidence to a record, or refuse. Returns the correlation identity dict."""
    if evidence_subject_id != record.subject_id:
        raise WrongSubjectEvidence(
            "evidence subject %r does not match record subject %r"
            % (evidence_subject_id, record.subject_id))
    expected = expected_correlation_id(record)
    if evidence_correlation_id != expected:
        raise CorrelationMismatch(
            "evidence correlation id %r does not match effect correlation id %r"
            % (evidence_correlation_id, expected))
    return {
        "effect_id": record.effect_id,
        "subject_id": record.subject_id,
        "correlation_id": expected,
        "evidence_ref": evidence_ref,
        "subject_match": True,
    }


def verify_correlation(record, evidence) -> dict:
    """Check a binding (or raw evidence) against a record; never raises, always reasoned."""
    if not isinstance(evidence, dict):
        return {"bound": False, "reason_code": "MALFORMED_EVIDENCE"}
    if evidence.get("subject_id") != record.subject_id:
        return {"bound": False, "reason_code": "WRONG_SUBJECT_EVIDENCE"}
    if evidence.get("correlation_id") != expected_correlation_id(record):
        return {"bound": False, "reason_code": "CORRELATION_MISMATCH"}
    if evidence.get("effect_id") != record.effect_id:
        return {"bound": False, "reason_code": "CORRELATION_MISMATCH"}
    return {"bound": True, "reason_code": "BOUND"}
