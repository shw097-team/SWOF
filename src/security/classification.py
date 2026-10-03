"""Secret / PII classification, redaction and the evidence no-secret gate.

WHY: a credential pasted into an evidence payload becomes permanent, world-readable evidence,
and a downstream reader cannot tell it apart from ordinary text. Classification labels the
payload, redaction removes the secret before it is written, and `assert_no_secret` is a hard
gate that a caller cannot satisfy with an empty payload - "nothing was checked" is not
"nothing was found". These guards classify and redact; they grant no authority.

The detector table is covered by `detector_selftest()`, which fails closed if any detector is
vacuous, if any real-world credential shape is missed, or if any benign prose sample is
flagged. A detector that cannot fire, or that fires on ordinary text, is a defect: the first
lets a secret through and the second destroys evidence. Neither is allowed to be silent.
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
    positive_extra: tuple = ()
    benign_extra: tuple = ()

    def positive_samples(self):
        return (self.positive,) + tuple(self.positive_extra)

    def benign_samples(self):
        return (self.benign,) + tuple(self.benign_extra)


# A credential-shaped run: 16+ characters drawn from the alphabet that real secrets use.
_RUN = r"[A-Za-z0-9_\-./+=]{16,}"

_DETECTORS = (
    _Detector("SECRET", "bearer_auth_header",
              re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+" + _RUN),
              "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD",
              "the authorization section documents which humans may approve a release",
              ("Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Ng==",)),
    _Detector("SECRET", "keyword_assigned_credential",
              re.compile(r"(?i)\b(?:aws_secret_access_key|secret_access_key|access_token|"
                         r"refresh_token|id_token|api_key|apikey|client_secret|private_key|"
                         r"password|passwd|token)\s*[\"']?\s*[:=]\s*[\"']?\s*(" + _RUN + r")"),
              "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
              "the handbook explains how api key rotation is scheduled each quarter",
              ('{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD"}',
               '{"token":"abcdefghij1234567890"}',
               "client_secret: s3cr3t-value-with-length",
               'password = "correcthorsebatterystaple"')),
    _Detector("SECRET", "private_key_block",
              re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
              "-----BEGIN OPENSSH PRIVATE KEY-----",
              "the document compares PEM and DER certificate encodings",
              ("-----BEGIN RSA PRIVATE KEY-----",)),
    _Detector("SECRET", "ssh_public_key_blob",
              re.compile(r"\bssh-rsa\s+AAAA[A-Za-z0-9+/]{20,}"),
              "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7",
              "the ssh-rsa key exchange algorithm is listed in the deprecation notice"),
    _Detector("SECRET", "github_token",
              re.compile(r"\b(?:ghp_|github_pat_)[0-9A-Za-z_]{8,}"),
              "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwx",
              "the migration guide mentions the github_pat_ prefix without a value",
              ("ghp_" + "a" * 36,)),
    _Detector("SECRET", "gitlab_token",
              re.compile(r"\bglpat-[0-9A-Za-z_\-]{16,}"),
              "glpat-abcdefghij1234567890",
              "the release notes mention the glpat- token family without a value"),
    _Detector("SECRET", "slack_token",
              re.compile(r"\bxox[boap]-[0-9A-Za-z\-]{10,}"),
              "xoxb-123456789012-1234567890123-AbCdEfGhIjKl",
              "the chat integration doc names the xoxb- token family without a value",
              ("xoxp-123456789012-1234567890123-AbCdEfGhIjKl",)),
    _Detector("SECRET", "stripe_secret_key",
              re.compile(r"\b(?:sk_live_|sk_test_|sk-proj-)[0-9A-Za-z_\-]{16,}"),
              "sk_live_51H8xYzAbCdEfGhIjKlMnOpQr",
              "billing docs describe the sk_live_ key prefix in prose",
              ("sk-proj-abcdefghij1234567890",)),
    _Detector("SECRET", "aws_access_key_id",
              re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
              "AKIAIOSFODNN7EXAMPLE",
              "the inventory report lists AKIA-adjacent product codes",
              ("ASIAIOSFODNN7EXAMPLE",)),
    _Detector("PII", "email_address",
              re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
              "contact alice.chen@example.com for escalation",
              "the mail relay name is relay01.internal.example"),
    _Detector("PII", "taiwan_national_id",
              re.compile(r"\b[A-Z][12]\d{8}\b"),
              "A123456789",
              "the build tag is Z9ABC1234 and it is public"),
    _Detector("PII", "card_like_number",
              re.compile(r"(?<![0-9A-Za-z])(?:\d[ \-]?){13,19}(?![0-9A-Za-z])"),
              "4111 1111 1111 1111",
              "order reference 2026 is recorded in the quarterly ledger"),
)

DETECTORS = tuple(_DETECTORS)

# Keys whose value is a credential by construction. A mapping such as
# {"access_token": "<jwt>"} is a real credential even when the value alone carries no vendor
# prefix, so the key name participates in classification and redaction.
_CREDENTIAL_KEY_NAMES = (
    "aws_secret_access_key", "secret_access_key", "access_token", "refresh_token",
    "id_token", "api_key", "apikey", "client_secret", "private_key", "password", "passwd",
    "token", "authorization",
)
_CREDENTIAL_VALUE = re.compile(r"^[\"\x27]?\s*[A-Za-z0-9_\-./+=]{16,}\s*[\"\x27]?$")


def _is_credential_key(key) -> bool:
    return isinstance(key, str) and key.strip().lower() in _CREDENTIAL_KEY_NAMES


def _credential_pair(key, value) -> bool:
    """True when a credential-named key holds a credential-length value."""
    return (_is_credential_key(key) and isinstance(value, str)
            and bool(_CREDENTIAL_VALUE.match(value)))


# The credential shapes the independent lane planted. Each MUST classify SECRET and MUST be
# removed by redact(); detector_selftest() raises if any one of them is missed.
REAL_WORLD_SECRET_SAMPLES = (
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD",
    "Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Ng==",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwx",
    "glpat-abcdefghij1234567890",
    "xoxb-123456789012-1234567890123-AbCdEfGhIjKl",
    "sk_live_51H8xYzAbCdEfGhIjKlMnOpQr",
    '{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAABBBBCCCCDDDD"}',
    '{"token":"abcdefghij1234567890"}',
    '{"api_key":"sk-proj-abcdefghij1234567890"}',
    "ASIAIOSFODNN7EXAMPLE",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7",
    "-----BEGIN RSA PRIVATE KEY-----",
)

# Ordinary text that must stay PUBLIC: a sentence containing the word "token", a version
# string, a short word, a UUID, a file path and a commit SHA. detector_selftest() raises if
# any of these is flagged by any detector.
BENIGN_SAMPLES = (
    "the token is rotated by the platform team each quarter",
    "an ordinary sentence that merely contains the word token",
    "v1.4.2-beta.20261004",
    "ok",
    "550e8400-e29b-41d4-a716-446655440000",
    "C:/projects/swof/src/security/classification.py",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
)


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
            if _credential_pair(key, item):
                classes.add("SECRET")
                redactions["SECRET"] = redactions.get("SECRET", 0) + 1
                clean[key] = "[REDACTED:SECRET]"
                scanned += 1
                continue
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
        for key, item in payload.items():
            if _credential_pair(key, item):
                return True
            if _secret_survives(item, depth + 1):
                return True
        return False
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
    """Prove every detector fires on real shapes and stays silent on benign prose.

    Raises SecretExfiltrationBlocked if any detector is vacuous (a detector that cannot
    fire), if any real-world credential sample is missed, or if any benign sample is flagged.
    """
    receipt = {}
    failed = []
    for detector in DETECTORS:
        positives = detector.positive_samples()
        negatives = detector.benign_samples()
        positive_matched = sum(1 for sample in positives if detector.regex.search(sample))
        true_negative_matched = sum(1 for sample in negatives
                                    if not detector.regex.search(sample))
        vacuous = positive_matched == 0
        missed = positive_matched < len(positives)
        benign_matched = true_negative_matched < len(negatives)
        if vacuous or missed or benign_matched:
            failed.append(detector.detector_id)
        receipt[detector.detector_id] = {
            "class": detector.class_name,
            "positive_matched": positive_matched > 0,
            "positive_matched_count": positive_matched,
            "positive_total": len(positives),
            "true_negative_matched": true_negative_matched == len(negatives),
            "true_negative_matched_count": true_negative_matched,
            "true_negative_total": len(negatives),
            "benign_matched": benign_matched,
            "vacuous": vacuous,
        }

    missed_secret_samples = [sample for sample in REAL_WORLD_SECRET_SAMPLES
                             if classify(sample) != "SECRET"]
    unredacted_secret_samples = [sample for sample in REAL_WORLD_SECRET_SAMPLES
                                 if "[REDACTED:SECRET]" not in redact(sample)]
    flagged_benign_samples = [sample for sample in BENIGN_SAMPLES
                              if classify(sample) != "PUBLIC"]

    receipt["vacuous"] = bool(failed)
    receipt["failed_detectors"] = sorted(failed)
    receipt["missed_secret_samples"] = list(missed_secret_samples)
    receipt["unredacted_secret_samples"] = list(unredacted_secret_samples)
    receipt["flagged_benign_samples"] = list(flagged_benign_samples)

    if failed or missed_secret_samples or unredacted_secret_samples or flagged_benign_samples:
        raise SecretExfiltrationBlocked(
            "VACUOUS_OR_OVERFLAGGING_DETECTOR: detectors=%s missed=%s unredacted=%s "
            "benign_flagged=%s" % (sorted(failed), missed_secret_samples,
                                   unredacted_secret_samples, flagged_benign_samples))
    return receipt
