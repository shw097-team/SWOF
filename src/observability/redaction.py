"""Security-safe logging: a secret must never reach a log sink.

WHY: a log line is exactly the place a credential leaks - it is copied to consoles, shipped to
aggregators, pasted into tickets and kept far longer than the secret. This module builds on
`security.classification` (W2-001) rather than re-implementing detection, because two detectors
would mean two different answers to "is this a secret?", and the weaker one decides nothing.

The gate is deliberately NOT satisfiable by an empty string or an empty payload: "nothing was
checked" is not "nothing was found". `assert_log_safe` refuses a NON-STRING outright (an
unscannable value is treated as hostile) and refuses any SECRET-class residue, so a call site
cannot pass by blanking the input.

Dict KEYS are checked too. `sanitize_evidence` redacts values only, so a credential used as a
key name would otherwise survive straight into the sink; a key that classifies SECRET is
refused rather than rewritten, because silently renaming a field corrupts the event shape.
"""
from __future__ import annotations

import security.classification as classification

SINK_SAFE = "[REDACTED:SECRET]"

_BENIGN_SCALARS = (bool, int, float, type(None))


class LogUnsafe(Exception):
    """A value that still carries a SECRET-class substring would have reached a log sink."""

    code = "ERR_LOG_UNSAFE"

    def __init__(self, message, class_name=None):
        super().__init__(message)
        self.class_name = class_name


def _receipt(redactions, scanned):
    total = sum(redactions.values())
    return {
        "redactions": dict(redactions),
        "scanned_items": scanned,
        "redacted_total": total,
        "safe": total == 0,
    }


def _redact_str(text):
    found = classification._hits(text)
    if not found:
        return text, {}
    counts = {}
    for _, _, class_name, _, _ in found:
        counts[class_name] = counts.get(class_name, 0) + 1
    return classification.redact(text, replacement=SINK_SAFE), counts


def redact_line(line):
    """Redact one log line. A non-string is refused (not coerced to an empty, "safe" string).

    Returns `(safe_line, receipt)` where the receipt reports what was removed:
    `{"redactions": {...}, "scanned_items": 1, "redacted_total": N, "safe": bool}`.
    """
    if not isinstance(line, str):
        raise LogUnsafe(
            "log line is %s, not a string: an unscannable value cannot be certified safe"
            % type(line).__name__)
    safe_line, counts = _redact_str(line)
    return safe_line, _receipt(counts, 1)


def redact_event(payload):
    """Redact a deep copy of a payload; the input is never mutated.

    Returns `(clean_payload, receipt)`. Any SECRET that survives (a secret in a dict key, or an
    unscannable value) is a hard failure: an unredacted secret must never reach a log sink. An
    empty top-level payload is refused, because "nothing was checked" is not "nothing was found".
    """
    _reject_keys(payload)
    clean, receipt = classification.sanitize_evidence(payload)
    _reject_survivors(clean)
    counts = dict(receipt.get("redactions", {}))
    scanned = receipt.get("scanned_items", 1)
    return clean, _receipt(counts, scanned)


def assert_log_safe(line):
    """Raise `LogUnsafe` unless the value is a scannable string with no SECRET residue."""
    if not isinstance(line, str):
        raise LogUnsafe(
            "log value is %s, not a string: an unscannable value cannot be certified safe"
            % type(line).__name__, class_name=None)
    if line.strip() == "":
        raise LogUnsafe(
            "empty log line: nothing was checked is not nothing was found", class_name=None)
    class_name = classification.classify(line)
    if class_name == "SECRET":
        raise LogUnsafe("SECRET-class content present in a value bound for a log sink",
                        class_name=class_name)
    return None


def _reject_keys(payload, depth=0):
    if depth > 32:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if classification.classify(key) == "SECRET":
                raise LogUnsafe(
                    "SECRET-class content used as a payload key: the value would be redacted "
                    "but the key would leak into the log sink", class_name="SECRET")
            _reject_keys(value, depth + 1)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            _reject_keys(item, depth + 1)


def _reject_survivors(clean, depth=0):
    if depth > 32:
        raise LogUnsafe("payload nesting exceeds the scanning depth limit")
    if isinstance(clean, str):
        if classification.classify(clean) == "SECRET":
            raise LogUnsafe(
                "SECRET-class substring survived redaction (unredactable key or non-string "
                "value): it must never reach a log sink", class_name="SECRET")
        return
    if isinstance(clean, dict):
        if not clean:
            raise LogUnsafe(
                "empty payload: nothing was checked is not nothing was found")
        for value in clean.values():
            _reject_survivors(value, depth=depth + 1)
        return
    if isinstance(clean, (list, tuple)):
        if not clean:
            raise LogUnsafe(
                "empty payload: nothing was checked is not nothing was found")
        for item in clean:
            _reject_survivors(item, depth=depth + 1)
        return
    if isinstance(clean, _BENIGN_SCALARS):
        return
    raise LogUnsafe(
        "unscannable %s value survived redaction: a value that cannot be scanned cannot be "
        "certified free of a secret" % type(clean).__name__, class_name="SECRET")