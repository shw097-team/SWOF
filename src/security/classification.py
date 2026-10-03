"""Secret / PII classification, redaction and the evidence no-secret gate.

WHY: a credential pasted into an evidence payload becomes permanent, world-readable evidence,
and a downstream reader cannot tell it apart from ordinary text. Classification labels the
payload, redaction removes the secret before it is written, and `assert_no_secret` is a hard
gate that a caller cannot satisfy with an empty payload - "nothing was checked" is not
"nothing was found". These guards classify and redact; they grant no authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CLASSES = ("PUBLIC", "INTERNAL", "PII", "SECRET")
_RANK = {name: index for index, name in enumerate(CLASSES)}


class SecretExfiltrationBlocked(Exception):
    """A SECRET-class value (or an unverifiable payload) would have reached evidence."""

    code = "ERR_SECRET_EXFILTRATION_BLOCKED"


@dataclass(frozen=True)
class _Detector:
    class_name: str
    detector_id: str
    regex: object
    positive: str
    benign: str


_DETECTORS = (
    _Detector("SECRET", "aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
              "AKIAIOSFODNN7EXAMPLE",
              "the inventory report lists AKIA-adjacent product codes"),
    _Detector("SECRET", "bearer_or_api_token",
              re.compile(r"(?i)\b(?:api[_-]?key|token|bearer|password|passwd|secret)"
                         r"\s*[:=]\s*[A-Za-z0-9_\-./+]{16,}"),
              "api_key = 9f8E7d6C5b4A3f2E1d0C",
              "the handbook explains how api key rotation is scheduled"),
    _Detector("SECRET", "private_key_block",
              re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
              "-----BEGIN OPENSSH PRIVATE KEY-----",
              "the document compares PEM and DER certificate encodings"),
    _Detector("PII", "email_address",
              re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
              "contact alice.chen@example.com for escalation",
              "the mail relay name is relay01.internal.example"),
    _Detector("PII", "taiwan_national_id",
              re.compile(r"\b[A-Z][12]\d{8}\b"),
              "A123456789",
              "the build tag is Z9ABC1234 and it is public"),
    _Detector("PII", "card_like_number",
              re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
              "4111 1111 1111 1111",
              "order reference 2026 is recorded in the quarterly ledger"),
)

DETECTORS = tuple(_DETECTORS)


def _hits(text):
    found = []
    for detector in DETECTORS:
        for match in detector.regex.finditer(text):
            found.append((match.start(), match.end(), detector.class_name,
                          detector.detector_id, match.group(0)))
    found.sort(key=lambda item: item[0])
    return found


def _highest(hits):
    best = "PUBLIC"
    for _, _, class_name, _, _ in hits:
        if _RANK[class_name] > _RANK[best]:
            best = class_name
    return best


def classify(text) -> str:
    """Return the HIGHEST class present; never raises."""
    if not isinstance(text, str):
        return "SECRET"
    return _highest(_hits(text))


def classify_many(values) -> dict[str, str]:
    """Classify each mapping value under its key; unparsable input classifies SECRET."""
    if not isinstance(values, dict):
        return {}
    return {key: classify(value) for key, value in values.items()}


def redact(text, *, replacement=None) -> str:
    """Replace each hit with `[REDACTED:<CLASS>]`; benign text is returned unchanged."""
    if not isinstance(text, str):
        return text
    out = []
    cursor = 0
    for start, end, class_name, _, _ in _hits(text):
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(replacement if replacement is not None else "[REDACTED:%s]" % class_name)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _walk(value, redactions, classes):
    if isinstance(value, str):
        found = _hits(value)
        if found:
            classes.add(_highest(found))
            for _, _, class_name, _, _ in found:
                redactions[class_name] = redactions.get(class_name, 0) + 1
        return redact(value), 1
    if isinstance(value, dict):
        clean = {}
        scanned = 0
        for key, item in value.items():
            clean_value, count = _walk(item, redactions, classes)
            clean[key] = clean_value
            scanned += count
        return clean, scanned
    if isinstance(value, list):
        clean_list = []
        scanned = 0
        for item in value:
            clean_item, count = _walk(item, redactions, classes)
            clean_list.append(clean_item)
            scanned += count
        return clean_list, scanned
    if isinstance(value, tuple):
        clean_items = []
        scanned = 0
        for item in value:
            clean_item, count = _walk(item, redactions, classes)
            clean_items.append(clean_item)
            scanned += count
        return tuple(clean_items), scanned
    return value, 1


def sanitize_evidence(payload) -> tuple[object, dict]:
    """Redact a deep copy of the payload and return `(clean_payload, receipt)`."""
    redactions = {}
    classes = set()
    clean, scanned = _walk(payload, redactions, classes)
    receipt = {
        "redactions": dict(redactions),
        "scanned_items": scanned,
        "classes_present": sorted(classes, key=lambda name: _RANK[name]),
        "clean": not redactions,
    }
    return clean, receipt


def _secret_survives(payload, depth=0):
    if depth > 32:
        return True
    if isinstance(payload, str):
        return classify(payload) == "SECRET"
    if isinstance(payload, dict):
        if not payload:
            return True
        return any(_secret_survives(item, depth + 1) for item in payload.values())
    if isinstance(payload, (list, tuple)):
        if not payload:
            return True
        return any(_secret_survives(item, depth + 1) for item in payload)
    return False


def assert_no_secret(payload) -> None:
    """Hard gate: raise unless the payload is a non-empty evidence mapping with no SECRET."""
    if not isinstance(payload, dict) or not payload:
        raise SecretExfiltrationBlocked(
            "empty or non-mapping payload: nothing was checked is not nothing was found")
    if _secret_survives(payload):
        raise SecretExfiltrationBlocked("SECRET-class value present in evidence payload")


def detector_selftest() -> dict:
    """Prove every detector is non-vacuous and does not over-flag its benign sample."""
    receipt = {}
    failures = []
    for detector in DETECTORS:
        positive_matched = bool(detector.regex.search(detector.positive))
        benign_matched = bool(detector.regex.search(detector.benign))
        vacuous = not positive_matched
        if vacuous or benign_matched:
            failures.append(detector.detector_id)
        receipt[detector.detector_id] = {
            "class": detector.class_name,
            "positive_matched": positive_matched,
            "benign_matched": benign_matched,
            "vacuous": vacuous,
        }
    receipt["vacuous"] = bool(failures)
    if failures:
        raise SecretExfiltrationBlocked(
            "VACUOUS_OR_OVERFLAGGING_DETECTOR: %s" % ", ".join(sorted(failures)))
    return receipt
