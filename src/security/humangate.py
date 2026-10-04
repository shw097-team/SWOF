"""Typed, exact-bound human approval tokens at the existing HumanGate seam.

WHY: a HumanGate that accepts any non-empty string is a syntactic gate, not an authority gate -
"approved" typed by the actor who wants the action is indistinguishable from a real approval, so
the gate refuses nothing. This module makes the approval a typed value object bound exactly to the
request it approves and to the currentness inputs at commit time, and makes the verifier the only
authority. The canonical bytes are RFC 8785 (JCS); the signature is a REAL Ed25519 verification
performed against a public key resolved from an injected trusted key registry, over the
RFC8785-framed payload. This library never trusts a shape for integrity and never reads a clock.

This is a refusal mechanism, not a second authority system. It grants nothing, produces no
Product/Semantic truth, and never reads the wall clock: `commit_time` and every generation are
explicit trusted inputs supplied by the caller.

W2 repair WO-SWOF-W2-R003 (schema fidelity): the runtime type must be STRICTER OR EQUAL to the
canonical registry, never broader. The token therefore carries the IF-06B ABI/envelope fields
(`if06b_version`, `payload_schema_version`, `min_reader_version`, `writer_version`,
`compatibility_class`, `evidence_link`) that the canonical ApprovalToken 1.0.0 schema requires, and
the verifier refuses an unsupported ABI major (`IF06B_VERSION_UNSUPPORTED`) or an unreadable
envelope (`DENY_TOKEN_SCHEMA`) before any authority check runs.

W2 repair WO-SWOF-W2-R004 (R4): the canonical payload is RFC8785 JCS (NOT json.dumps), prefixed
with a fixed domain frame; the key registry became a public-key RESOLVER `registry(issuer_id,
key_id, key_generation)` returning bytes or a cryptography key, and the verifier performs a real
`Ed25519PublicKey.verify` over the framed bytes; `approval_basis_hash` is RECOMPUTED (not merely
shape-checked); request->decision->token lineage (`request_id`/`decision_id`) is exact-bound;
audience, declared generations and the independent-checker flag are mandatory wherever canonical
says so. RUIN/UNKNOWN_RUIN precedence and the single gate predicate live in `rights.py`.
"""
from __future__ import annotations

import base64
import decimal as _decimal
import hashlib
import math
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

INTEGRITY_PROFILE_ID = "SWOF-HG-INTEGRITY-001"

TOKEN_STATES = ("ACTIVE", "CONSUMED", "REVOKED", "EXPIRED")
AUTHN_ASSURANCE_CLASSES = ("AAC1", "AAC2", "AAC3")

# IF-06B ABI/envelope constants (canonical ApprovalToken 1.0.0). The reader ABI is 1.0; a token
# written for a newer major cannot be read, and an unrecognised writer/compatibility class is a
# hard failure rather than a silent downgrade.
IF06B_ABI_MAJOR = "1"
READER_ABI = "1.0"
PAYLOAD_SCHEMA_VERSION = "1.0.0"
KNOWN_WRITER_VERSIONS = ("DOC03-r2",)
KNOWN_COMPATIBILITY_CLASSES = ("STRICT_MAJOR_ADDITIVE_MINOR",)

# R4: the fixed domain-separation frame that must prefix every signed canonical payload.
DOMAIN_FRAME = b"SWOF:PI-PKG-06:DOC-03:APPROVAL-TOKEN:V1\x00"
# R4: the approval-basis domain separator (PI06 section 15.5).
APPROVAL_BASIS_FRAME = b"SWOF-D03-APPROVAL-BASIS-V1\n"

JCS_PROFILE = "RFC8785"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

# R4 3.6: exact dotted-numeric version syntax. `^\d+\.\d+$` for the ABI fields and
# `^\d+\.\d+\.\d+$` for the payload schema version. "1" and "1.0.0.0" are refused.
_ABI_VERSION_RE = re.compile(r"^\d+\.\d+$")
_SCHEMA_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

_DIGEST_FIELDS = ("subject_hash", "effect_digest", "consumer_audience_hash", "approval_basis_hash")

_REQUIRED_TEXT_FIELDS = (
    "token_id", "request_id", "decision_id", "subject", "semantic_version", "actor", "operation",
    "target_system", "environment", "purpose_ref", "data_class", "approver", "authority_class",
    "approver_authn_context_ref", "reauthenticated_at", "issued_at", "expires_at", "nonce",
    "token_state", "consumer", "integrity_profile_id", "issuer_id", "key_id",
)

_GENERATION_FIELDS = ("authn_session_generation", "credential_generation", "key_generation")

# R4 3.5: the generation set a request may declare. Every declared generation must be present in
# `ctx` and equal the token's; a declaration the context cannot answer is DENY_STALE_GENERATION.
_GENERATION_REQUEST_FIELDS = (
    "rights_generation", "consent_generation", "security_policy_generation", "provider_generation",
    "ruin_generation", "authn_session_generation", "credential_generation", "key_generation",
    "revocation_generation",
)

# ctx generation attribute -> matching token attribute. None means the token carries no analog,
# so a context that requires it makes the token stale (fail closed).
_GENERATION_BINDINGS = (
    ("authn_session_generation", "authn_session_generation"),
    ("credential_generation", "credential_generation"),
    ("rights_generation", None),
    ("consent_generation", None),
    ("security_policy_generation", None),
    ("provider_generation", None),
    ("ruin_generation", None),
    ("revocation_generation", None),
)

_HUMAN_REF_PREFIX = "human:"
_NON_HUMAN_REF_PREFIXES = (
    "model:", "tool:", "provider:", "agent:", "mcp:", "a2a:", "automation:", "svc:", "service:",
)

# WO-SWOF-W2-R005 (R5): the ONE canonical classification domains (PI-PKG-06 DOC-03).
# `effect_risk_tier` carries RUIN / UNKNOWN_RUIN INSIDE its enum; `ruin_class` does NOT exist in the
# canonical source. `permission_class` is P0..P5 and `autonomy_tier` is T0..T3 (DOC-03 line 778,
# line 876, line 1069 and the HumanGatePolicy block).
EFFECT_RISK_TIERS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "RUIN", "UNKNOWN_RUIN")
PERMISSION_CLASSES = ("P0", "P1", "P2", "P3", "P4", "P5")
AUTONOMY_TIERS = ("T0", "T1", "T2", "T3")

# EffectRiskTier tiers that demand an exact-bound Human token by RISK alone (LOW/MEDIUM do not).
_TOKEN_REQUIRED_RISK_TIERS = frozenset({"HIGH", "CRITICAL", "RUIN", "UNKNOWN_RUIN"})
# Permission-class floor that demands a token (TOK-INV-001).
_TOKEN_REQUIRED_PERMISSION_CLASSES = frozenset({"P3", "P4", "P5"})
# P3+ permission floor that also requires a rollback ref.
_ROLLBACK_TRIGGER_TIERS = ("P3", "P4", "P5")

# The NON-CANONICAL legacy alias vocabulary. `ruin_class` does not exist in the canonical source; it
# is accepted ONLY when the canonical `effect_risk_tier` is absent, and it may never weaken a
# present canonical value. Its baseline value is "NONE" (no ruin).
_LEGACY_RUIN_CLASSES = ("NONE", "RUIN", "UNKNOWN_RUIN")

# The documented refusal-code set for ApprovalToken verification (first-fail order). R4 adds
# DENY_APPROVAL_BASIS (recomputed basis), DENY_AUDIENCE_MISMATCH (mandatory audience),
# DENY_STALE_GENERATION (mandatory declared generations) and the ruin precedence codes
# HARD_VETO_RUIN / SAFE_STOP_UNKNOWN_RUIN shared with the gate predicate.
APPROVAL_DENY_CODES = (
    "NOT_A_CANONICAL_APPROVAL_TOKEN", "DENY_TOKEN_SCHEMA", "IF06B_VERSION_UNSUPPORTED",
    "DENY_TOKEN_STATE", "HARD_VETO_RUIN", "SAFE_STOP_UNKNOWN_RUIN", "DENY_EXACT_BINDING",
    "DENY_AUDIENCE_MISMATCH", "DENY_TOKEN_TIME", "DENY_FALSE_AUTHORITY", "DENY_AUTHN",
    "DENY_STALE_GENERATION", "DENY_NO_ROLLBACK", "DENY_APPROVAL_BASIS", "DENY_TOKEN_INTEGRITY",
    "DENY_REPLAY", "DENY_T3_CHECKER",
)

# ---------------------------------------------------------------------------------------------
# RFC 8785 (JCS) canonical serialisation. This is the profile SWOF signs; it is NOT
# `json.dumps(sort_keys=True)` - that approximates it and silently emits non-canonical numbers
# (e.g. `1.0` for the integer `1`) and does not sort by UTF-16 code units.
# ---------------------------------------------------------------------------------------------
_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r",
            "\t": "\\t"}
_MAX_SAFE_INTEGER = 2 ** 53 - 1


class JCSError(ValueError):
    """A value cannot be serialised in RFC 8785 canonical form -> fail closed, never guess."""


def _jcs_escape(text: str) -> str:
    out = ['"']
    for ch in text:
        escaped = _ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif ch < " ":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(value) -> str:
    """A number per RFC 8785 / ECMAScript `Number::toString`. Raise rather than emit a wrong form.

    Integers render without a fraction or exponent; a fraction-free float renders as an integer
    (`1.0` -> `1`) and `-0.0` -> `0`. Non-integer floats use Python's shortest round-tripping
    `repr` expanded to plain decimal notation inside the range ES6 prints without an exponent
    ([1e-6, 1e21)); anything outside that provable range raises instead of guessing. NaN and
    Infinity are not JSON numbers and raise.
    """
    if isinstance(value, bool):
        raise JCSError("bool is not a number")
    if isinstance(value, int):
        if -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            return str(value)
        raise JCSError("integer outside the RFC8785 IEEE-754 safe range")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise JCSError("NaN/Infinity are not JSON numbers")
        if value == 0.0:
            return "0"
        magnitude = abs(value)
        if value.is_integer() and magnitude < 1e21:
            return str(int(value))
        if 1e-6 <= magnitude < 1e21:
            text = repr(value)
            if "e" in text or "E" in text:
                text = format(_decimal.Decimal(text), "f")
            return text
        raise JCSError("float outside the provable RFC8785 decimal range")
    raise JCSError("not a JSON number: %r" % type(value).__name__)


def _jcs_value(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_escape(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_value(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise JCSError("object keys must be strings")
        items = []
        for key in sorted(value, key=lambda k: k.encode("utf-16-be")):
            items.append("%s:%s" % (_jcs_escape(key), _jcs_value(value[key])))
        return "{" + ",".join(items) + "}"
    raise JCSError("unsupported JSON type: %r" % type(value).__name__)


def jcs_dumps(obj) -> bytes:
    """RFC 8785 JCS canonical bytes. Profile is `RFC8785`; this is NOT json.dumps(sort_keys=True).

    Keys sort by UTF-16 code units, strings use the JSON escapes with no unnecessary escapes and
    are emitted as UTF-8, numbers follow ECMAScript `Number::toString`, and there is no
    insignificant whitespace. A value that cannot be serialised canonically raises `JCSError`
    instead of emitting an approximate form.
    """
    return _jcs_value(obj).encode("utf-8")


def canonical_payload_bytes(token) -> bytes:
    """The exact bytes a verifier signs/verifies: DOMAIN_FRAME || JCS(token without `signature`).

    These are the bytes the trusted key resolver's Ed25519 public key verifies the signature
    against. JCS is applied to the token body with the `signature` field removed, and the fixed
    domain frame is prefixed for domain separation.
    """
    body = {key: value for key, value in _token_body(token).items() if key != "signature"}
    return DOMAIN_FRAME + jcs_dumps(body)


def approval_basis_hash(decision_basis_hash, effect_digest, generation_bundle_digest,
                        rollback_digest, consumer_audience_hash, if06b_version) -> str:
    """SHA-256 hex of b"SWOF-D03-APPROVAL-BASIS-V1\\n" || the six fields joined in that exact order.

    The six fields are joined with a single newline separator in this order: decision_basis_hash,
    effect_digest, generation_bundle_digest, rollback_digest, consumer_audience_hash,
    if06b_version.
    """
    material = "\n".join((
        "" if decision_basis_hash is None else str(decision_basis_hash),
        "" if effect_digest is None else str(effect_digest),
        "" if generation_bundle_digest is None else str(generation_bundle_digest),
        "" if rollback_digest is None else str(rollback_digest),
        "" if consumer_audience_hash is None else str(consumer_audience_hash),
        "" if if06b_version is None else str(if06b_version),
    ))
    return hashlib.sha256(APPROVAL_BASIS_FRAME + material.encode("utf-8")).hexdigest()


def _token_body(token) -> dict:
    """The token as a mapping, without deep-copying containers (the canonical form must see the
    exact field values)."""
    return {name: getattr(token, name) for name in token.__dataclass_fields__}


@dataclass(frozen=True)
class ApprovalDecision:
    """Verifier outcome. `ok` is the only field to trust."""

    ok: bool
    code: str
    detail: str = ""


@dataclass(frozen=True)
class ApprovalToken:
    """A human approval value object (PI-PKG-06::DOC-03 ApprovalToken 1.0.0).

    Every field carries a fail-closed default so a partially-populated object can be constructed
    and then refused by shape validation; the verifier, not this value object, is the authority.
    """

    token_id: str = ""
    request_id: str = ""
    decision_id: str = ""
    subject: str = ""
    subject_hash: str = ""
    semantic_version: str = ""
    actor: str = ""
    operation: str = ""
    target_system: str = ""
    resource: tuple[str, ...] = ()
    environment: str = ""
    purpose_ref: str = ""
    scope: tuple[str, ...] = ()
    data_class: str = ""
    effect_digest: str = ""
    consumer_audience_hash: str = ""
    approver: str = ""
    authority_class: str = ""
    approver_authn_context_ref: str = ""
    authn_assurance_class: str = ""
    reauthenticated_at: str = ""
    authn_session_generation: int | None = None
    credential_generation: int | None = None
    approval_basis_hash: str = ""
    if06b_version: str = IF06B_ABI_MAJOR + ".0"
    payload_schema_version: str = PAYLOAD_SCHEMA_VERSION
    min_reader_version: str = READER_ABI
    writer_version: str = KNOWN_WRITER_VERSIONS[0]
    compatibility_class: str = KNOWN_COMPATIBILITY_CLASSES[0]
    evidence_link: str = ""
    independent_checker_required: bool = False
    independent_checker_evidence_ref: str = ""
    issued_at: str = ""
    expires_at: str = ""
    nonce: str = ""
    rollback_ref: str = ""
    token_state: str = ""
    consumer: str = ""
    integrity_profile_id: str = ""
    issuer_id: str = ""
    key_id: str = ""
    key_generation: int | None = None
    signature: str = ""


@dataclass(frozen=True)
class ApprovalRequest:
    """What is being approved: the exact action/effect the token must bind to."""

    subject: str = ""
    subject_hash: str = ""
    semantic_version: str = ""
    actor: str = ""
    operation: str = ""
    # WO-SWOF-W2-R006 (R6): the canonical DOC-03 action_class axis. A DECLARED class must be a
    # canonical operation/action value; an unrecognised declared class is unclassifiable and the gate
    # SAFE-STOPS rather than guessing a benign mapping. Absent (None) means "resolve from `operation`".
    operation_class: str | None = None
    target_system: str = ""
    resource: tuple[str, ...] = ()
    environment: str = ""
    purpose_ref: str = ""
    scope: tuple[str, ...] = ()
    data_class: str = ""
    effect_digest: str = ""
    consumer_audience_hash: str = ""
    # R5: absent (None) is DISTINCT from present-but-invalid; a present value outside the canonical
    # domain fails closed in the gate, and an absent classification is never a permissive default.
    effect_risk_tier: str | None = None
    permission_class: str | None = None
    autonomy_tier: str | None = None
    required_authority: str = ""
    rollback_ref: str = ""
    independent_checker_required: bool = False
    ruin_class: str = "NONE"
    request_id: str = ""
    decision_id: str = ""
    decision_basis_hash: str = ""
    generation_bundle_digest: str = ""
    rollback_digest: str = ""
    # R4 3.5: the generation set this request declares. A declared generation must be present in
    # `ctx` and equal the token's; a silent skip is never allowed.
    authn_session_generation: int | None = None
    credential_generation: int | None = None
    key_generation: int | None = None
    rights_generation: int | None = None
    consent_generation: int | None = None
    security_policy_generation: int | None = None
    provider_generation: int | None = None
    ruin_generation: int | None = None
    revocation_generation: int | None = None


@dataclass(frozen=True)
class VerificationContext:
    """The trusted current-at-commit inputs. Nothing here is read from the wall clock.

    `trusted_key_registry` is a key RESOLVER, not a boolean verifier. It is called as
    `registry(issuer_id, key_id, key_generation)` and MUST return the Ed25519 public key as
    `bytes` (32) or a `cryptography` public-key object. Anything else - `None`, an exception, a
    non-callable, or a callable that cannot supply a key - fails closed with DENY_TOKEN_INTEGRITY.
    The verifier then performs a REAL `Ed25519PublicKey.verify(signature, framed_bytes)`; this is
    not a shape check.

    `expected_consumer_audience_hash` is mandatory for a gated route: a gated request whose
    audience is absent or malformed is refused with DENY_AUDIENCE_MISMATCH.
    """

    commit_time: str = ""
    rights_generation: int | None = None
    consent_generation: int | None = None
    security_policy_generation: int | None = None
    provider_generation: int | None = None
    ruin_generation: int | None = None
    authn_session_generation: int | None = None
    credential_generation: int | None = None
    key_generation: int | None = None
    revocation_generation: int | None = None
    expected_consumer_audience_hash: str | None = None
    trusted_key_registry: object = None
    nonce_ledger: object = None
    independent_checker_evidence_ref: str = ""
    max_reauth_age_seconds: int | float | None = None


class NonceLedger:
    """In-memory consume-once nonce store. A second reserve of the same nonce returns False."""

    def __init__(self):
        self._lock = threading.Lock()
        self._seen = set()

    def reserve(self, nonce) -> bool:
        if not isinstance(nonce, str) or not nonce.strip():
            return False
        with self._lock:
            if nonce in self._seen:
                return False
            self._seen.add(nonce)
            return True


def _deny(code, detail=""):
    return ApprovalDecision(False, code, detail)


def _is_nonempty_str(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_str_tuple(value) -> bool:
    if not isinstance(value, tuple) or not value:
        return False
    if not all(isinstance(item, str) and item for item in value):
        return False
    return len(set(value)) == len(value)


def _is_int_or_none(value) -> bool:
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


# A canonical-enum classification is one of these three states. ABSENT (None) is DISTINCT from
# MALFORMED (present but not a member of the canonical set); a malformed value fails closed and is
# never silently coerced to a permissive default (DOC-03 15.6).
_CLASS_ABSENT = "ABSENT"
_CLASS_VALID = "VALID"
_CLASS_MALFORMED = "MALFORMED"


def _classify_domain(value, domain):
    """(state, value) for a canonical enum: ABSENT (None), VALID (a member), else MALFORMED."""
    if value is None:
        return (_CLASS_ABSENT, None)
    if isinstance(value, str) and value in domain:
        return (_CLASS_VALID, value)
    return (_CLASS_MALFORMED, value)


def classify_effect_risk_tier(request):
    """The canonical EffectRiskTier classification of a request as a (state, value) pair."""
    return _classify_domain(getattr(request, "effect_risk_tier", None), EFFECT_RISK_TIERS)


def classify_permission_class(request):
    """The canonical PermissionClass classification of a request as a (state, value) pair."""
    return _classify_domain(getattr(request, "permission_class", None), PERMISSION_CLASSES)


def classify_autonomy_tier(request):
    """The canonical AutonomyTier classification of a request as a (state, value) pair."""
    return _classify_domain(getattr(request, "autonomy_tier", None), AUTONOMY_TIERS)


def classify_legacy_ruin_class(request):
    """The NON-CANONICAL legacy `ruin_class` alias as a (state, value) pair.

    `ruin_class` does not exist in the canonical source. Its baseline value is "NONE", so a value is
    either a recognised legacy value (VALID) or an unverifiable value (MALFORMED, fail closed).
    """
    value = getattr(request, "ruin_class", "NONE")
    if isinstance(value, str) and value in _LEGACY_RUIN_CLASSES:
        return (_CLASS_VALID, value)
    return (_CLASS_MALFORMED, value)


def ruin_precedence_code(request):
    """The HARD_VETO_RUIN / SAFE_STOP_UNKNOWN_RUIN code for a request, or None when non-ruin.

    RUIN / UNKNOWN_RUIN are carried INSIDE the canonical EffectRiskTier enum (`effect_risk_tier`);
    there is no canonical `ruin_class` field. Resolution order, fail closed throughout:

      1. a present-but-malformed `effect_risk_tier` is unclassifiable risk -> SAFE_STOP;
      2. a present-but-unrecognised legacy `ruin_class` alias is an unknown signal -> SAFE_STOP;
      3. canonical `effect_risk_tier` == "RUIN" -> HARD_VETO_RUIN;
         canonical `effect_risk_tier` == "UNKNOWN_RUIN" -> SAFE_STOP_UNKNOWN_RUIN;
      4. ONLY when the canonical field is ABSENT may the legacy alias raise the same codes; the
         alias can never weaken a present canonical value (DOC-03 line 476: a proposed
         consequential effect classified RUIN -> HARD_VETO regardless of Human token).
    """
    tier_state, tier = classify_effect_risk_tier(request)
    if tier_state == _CLASS_MALFORMED:
        return "SAFE_STOP_UNKNOWN_RUIN"
    legacy_state, legacy = classify_legacy_ruin_class(request)
    if legacy_state == _CLASS_MALFORMED:
        return "SAFE_STOP_UNKNOWN_RUIN"
    if tier == "RUIN":
        return "HARD_VETO_RUIN"
    if tier == "UNKNOWN_RUIN":
        return "SAFE_STOP_UNKNOWN_RUIN"
    if tier_state == _CLASS_ABSENT:
        if legacy == "RUIN":
            return "HARD_VETO_RUIN"
        if legacy == "UNKNOWN_RUIN":
            return "SAFE_STOP_UNKNOWN_RUIN"
    return None


def _epoch(rfc3339):
    """Parse an RFC3339 UTC instant to a POSIX timestamp, or None if it is not well formed."""
    if not isinstance(rfc3339, str) or not _ISO_UTC_RE.match(rfc3339):
        return None
    text = rfc3339
    if "." in text:
        head, _, tail = text.partition(".")
        text = head + tail
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc).timestamp()


def _is_human_ref(ref) -> bool:
    if not _is_nonempty_str(ref):
        return False
    lowered = ref.strip().lower()
    if any(lowered.startswith(prefix) for prefix in _NON_HUMAN_REF_PREFIXES):
        return False
    return lowered.startswith(_HUMAN_REF_PREFIX)


def _version_tuple(value):
    """A dotted-numeric version as an int tuple, or None when it is not well formed."""
    if not isinstance(value, str) or not value:
        return None
    parts = value.split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _envelope_error(token):
    """The IF-06B ABI/envelope gate (canonical ApprovalToken 1.0.0), fail closed.

    Rule 1 owns its canonical code IF06B_VERSION_UNSUPPORTED; rules 2-6 reuse the
    DENY_TOKEN_SCHEMA family so no downstream consumer needs a new code. The version fields must
    match their EXACT syntax - `^\\d+\\.\\d+$` for `if06b_version`/`min_reader_version` and
    `^\\d+\\.\\d+\\.\\d+$` for `payload_schema_version` - so "1" and "1.0.0.0" are refused.
    """
    abi = getattr(token, "if06b_version", None)
    if not isinstance(abi, str) or not _ABI_VERSION_RE.match(abi):
        return "IF06B_VERSION_UNSUPPORTED"
    if abi.split(".")[0] != IF06B_ABI_MAJOR:
        return "IF06B_VERSION_UNSUPPORTED"
    if not isinstance(token.payload_schema_version, str) \
            or not _SCHEMA_VERSION_RE.match(token.payload_schema_version) \
            or token.payload_schema_version != PAYLOAD_SCHEMA_VERSION:
        return "DENY_TOKEN_SCHEMA"
    if not isinstance(token.min_reader_version, str) \
            or not _ABI_VERSION_RE.match(token.min_reader_version):
        return "DENY_TOKEN_SCHEMA"
    reader = _version_tuple(READER_ABI)
    required_reader = _version_tuple(token.min_reader_version)
    if required_reader is None or required_reader > reader:
        return "DENY_TOKEN_SCHEMA"
    if token.writer_version not in KNOWN_WRITER_VERSIONS:
        return "DENY_TOKEN_SCHEMA"
    if token.compatibility_class not in KNOWN_COMPATIBILITY_CLASSES:
        return "DENY_TOKEN_SCHEMA"
    if not _is_nonempty_str(token.evidence_link):
        return "DENY_TOKEN_SCHEMA"
    return None


def _schema_errors(token):
    """Every way the token fails the canonical shape, in deterministic field order."""
    errors = []
    for name in _REQUIRED_TEXT_FIELDS:
        if not _is_nonempty_str(getattr(token, name, None)):
            errors.append("%s:missing_or_malformed" % name)
    for name in _DIGEST_FIELDS:
        value = getattr(token, name, None)
        if not isinstance(value, str) or not _DIGEST_RE.match(value):
            errors.append("%s:not_64_lower_hex" % name)
    for name in ("resource", "scope"):
        if not _is_str_tuple(getattr(token, name, None)):
            errors.append("%s:not_nonempty_unique_string_tuple" % name)
    for name in _GENERATION_FIELDS:
        if not _is_int_or_none(getattr(token, name, None)):
            errors.append("%s:not_int_or_none" % name)
    if token.token_state not in TOKEN_STATES:
        errors.append("token_state:not_canonical")
    if token.integrity_profile_id != INTEGRITY_PROFILE_ID:
        errors.append("integrity_profile_id:not_%s" % INTEGRITY_PROFILE_ID)
    if not isinstance(token.signature, str) or not _SIGNATURE_RE.match(token.signature):
        errors.append("signature:not_86_base64url")
    if not isinstance(token.independent_checker_required, bool):
        errors.append("independent_checker_required:not_bool")
    if not isinstance(token.rollback_ref, str):
        errors.append("rollback_ref:not_str")
    if not isinstance(token.independent_checker_evidence_ref, str):
        errors.append("independent_checker_evidence_ref:not_str")
    return errors


def _binding_errors(token, request):
    """Exact binding of the token to the request (TOK-INV-002), lineage included (R4 3.4)."""
    errors = []
    scalar_fields = (
        "subject", "subject_hash", "semantic_version", "actor", "operation", "target_system",
        "environment", "purpose_ref", "data_class", "effect_digest", "consumer_audience_hash",
        "request_id", "decision_id",
    )
    for name in scalar_fields:
        if getattr(token, name, None) != getattr(request, name, None):
            errors.append(name)
    if not _is_str_tuple(getattr(request, "resource", None)):
        errors.append("request.resource:malformed")
    elif set(token.resource) != set(request.resource):
        errors.append("resource")
    if not _is_str_tuple(getattr(request, "scope", None)):
        errors.append("request.scope:malformed")
    elif set(token.scope) != set(request.scope):
        errors.append("scope")
    return errors


def _ruin_route_error(request):
    """RUIN/UNKNOWN_RUIN precedence for the token verifier (see `ruin_precedence_code`).

    Derived from the canonical `effect_risk_tier`; a valid token can NEVER authorize a ruin class.
    """
    return ruin_precedence_code(request)

def _declaration_errors(request, ctx):
    """The declared-generation rule (R4 3.5), fail closed.

    Every generation the REQUEST declares must ALSO be present in `ctx` and equal it; a mismatch
    or an unanswerable declaration (ctx is None) is DENY_STALE_GENERATION - never a silent skip.
    The token side of each binding is checked separately by `_GENERATION_BINDINGS`.
    """
    errors = []
    for name in _GENERATION_REQUEST_FIELDS:
        declared = getattr(request, name, None)
        if declared is None:
            continue
        if not _is_int_or_none(declared) or isinstance(declared, bool):
            errors.append("%s:declared_malformed" % name)
            continue
        ctx_value = getattr(ctx, name, None)
        if ctx_value is None:
            errors.append("%s:declared_but_absent_in_ctx" % name)
            continue
        if not _is_int_or_none(ctx_value) or isinstance(ctx_value, bool):
            errors.append("%s:ctx_malformed" % name)
            continue
        if ctx_value != declared:
            errors.append("%s:request_vs_ctx_mismatch" % name)
    return errors
def _resolve_public_key(registry, issuer_id, key_id, key_generation):
    """Resolve an Ed25519 public key from the injected resolver, or None on any failure.

    The resolver is called as `registry(issuer_id, key_id, key_generation)` and must return bytes
    (32) or a cryptography public-key object. Anything else - `None`, a non-callable, a callable
    that raises, or a callable with incompatible arity - fails closed -> None.
    """
    if registry is None or not callable(registry):
        return None
    try:
        resolved = registry(issuer_id, key_id, key_generation)
    except Exception:
        return None
    if resolved is None:
        return None
    if isinstance(resolved, (bytes, bytearray)):
        return bytes(resolved)
    return resolved


def _verify_signature(token, ctx) -> bool:
    """A REAL Ed25519 verification over the RFC8785-framed canonical bytes.

    Resolves the Ed25519 public key from the injected trusting resolver and runs
    `Ed25519PublicKey.from_public_bytes(key).verify(signature, canonical_payload_bytes(token))`.
    The signature must be base64url WITHOUT padding decoding to exactly 64 bytes. Any failure -
    an unknown key, a wrong key/generation, a malformed signature, a wrong-field payload, or an
    InvalidSignature - fails closed (returns False). This is not a shape check.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return False

    key = _resolve_public_key(ctx.trusted_key_registry, token.issuer_id, token.key_id,
                              token.key_generation)
    if key is None:
        return False
    raw_signature = token.signature
    if not isinstance(raw_signature, str) or not _SIGNATURE_RE.match(raw_signature):
        return False
    try:
        padding = "=" * (-len(raw_signature) % 4)
        signature = base64.urlsafe_b64decode(raw_signature + padding)
    except Exception:
        return False
    if len(signature) != 64:
        return False
    payload = canonical_payload_bytes(token)
    try:
        if isinstance(key, (bytes, bytearray)):
            public_key = Ed25519PublicKey.from_public_bytes(bytes(key))
        else:
            public_key = key
        public_key.verify(signature, payload)
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def verify_approval_token(token, request, ctx) -> ApprovalDecision:
    """First-fail, deterministic verification of an exact-bound human approval token.

    Order: non-canonical token -> shape -> envelope -> token_state -> ruin precedence -> exact
    binding (incl. lineage) -> audience -> time -> false authority (incl. approver != actor) ->
    authn -> generations -> rollback -> basis recompute -> integrity (real Ed25519 over the
    RFC8785-framed bytes) -> replay -> checker -> T3. A merely-invalid token never raises; a
    non-canonical input object type fails closed with a typed decision too.
    """
    if not isinstance(token, ApprovalToken):
        return _deny("NOT_A_CANONICAL_APPROVAL_TOKEN", "token is not an ApprovalToken")
    if not isinstance(request, ApprovalRequest) or not isinstance(ctx, VerificationContext):
        return _deny("NOT_A_CANONICAL_APPROVAL_TOKEN",
                     "request/ctx must be canonical objects")
    # R5: RUIN/UNKNOWN_RUIN precedence is DERIVED FROM THE CANONICAL `effect_risk_tier` field and
    # evaluated FIRST: no token can satisfy it and no other approval consideration may mask it. A
    # malformed risk tier or a malformed legacy `ruin_class` alias is unknown ruin -> SAFE STOP.
    ruin = _ruin_route_error(request)
    if ruin is not None:
        return _deny(ruin, "ruin precedence refuses any token")

    errors = _schema_errors(token)
    if errors:
        return _deny("DENY_TOKEN_SCHEMA", ";".join(errors))

    envelope = _envelope_error(token)
    if envelope is not None:
        return _deny(envelope, "IF-06B envelope refused")

    if token.token_state != "ACTIVE":
        return _deny("DENY_TOKEN_STATE", "token_state=%s" % token.token_state)

    binding = _binding_errors(token, request)
    if binding:
        return _deny("DENY_EXACT_BINDING", ";".join(binding))

    # R4 3.5: a gated route requires a trustworthy expected audience; absent/malformed fails closed.
    expected_audience = ctx.expected_consumer_audience_hash
    if not isinstance(expected_audience, str) or not _DIGEST_RE.match(expected_audience):
        return _deny("DENY_AUDIENCE_MISMATCH", "expected consumer audience hash unavailable")
    if expected_audience != token.consumer_audience_hash:
        return _deny("DENY_AUDIENCE_MISMATCH", "consumer audience hash mismatch")

    commit_epoch = _epoch(ctx.commit_time)
    if commit_epoch is None:
        return _deny("DENY_TOKEN_TIME", "commit_time missing or malformed")
    issued_epoch = _epoch(token.issued_at)
    expires_epoch = _epoch(token.expires_at)
    if issued_epoch is None or expires_epoch is None:
        return _deny("DENY_TOKEN_TIME", "issued_at/expires_at malformed")
    if not (issued_epoch <= commit_epoch < expires_epoch):
        return _deny("DENY_TOKEN_TIME", "commit_time outside [issued_at, expires_at)")

    if not _is_human_ref(token.approver):
        return _deny("DENY_FALSE_AUTHORITY",
                     "approver=%r is not a human principal ref" % token.approver)
    if not _is_human_ref(token.actor):
        return _deny("DENY_FALSE_AUTHORITY", "actor=%r is not a human principal ref" % token.actor)
    if token.approver.strip() == token.actor.strip():
        return _deny("DENY_FALSE_AUTHORITY", "approver must not be the actor")

    if token.authn_assurance_class not in AUTHN_ASSURANCE_CLASSES:
        return _deny("DENY_AUTHN", "authn_assurance_class=%r" % token.authn_assurance_class)
    reauth_epoch = _epoch(token.reauthenticated_at)
    if reauth_epoch is None:
        return _deny("DENY_AUTHN", "reauthenticated_at malformed")
    max_age = ctx.max_reauth_age_seconds
    if not isinstance(max_age, (int, float)) or isinstance(max_age, bool) or max_age <= 0:
        return _deny("DENY_AUTHN", "max_reauth_age_seconds unavailable")
    age = commit_epoch - reauth_epoch
    if age < 0 or age > max_age:
        return _deny("DENY_AUTHN", "reauthenticated_at not within max_reauth_age_seconds")

    declaration_errors = _declaration_errors(request, ctx)
    if declaration_errors:
        return _deny("DENY_STALE_GENERATION", ";".join(declaration_errors))

    for ctx_name, token_name in _GENERATION_BINDINGS:
        ctx_value = getattr(ctx, ctx_name)
        if ctx_value is None:
            continue
        if not _is_int_or_none(ctx_value):
            return _deny("DENY_STALE_GENERATION", "%s malformed" % ctx_name)
        if token_name is None:
            return _deny("DENY_STALE_GENERATION", "token carries no %s" % ctx_name)
        if getattr(token, token_name) != ctx_value:
            return _deny("DENY_STALE_GENERATION", "%s mismatch" % ctx_name)

    risk = getattr(request, "effect_risk_tier", "")
    permission = getattr(request, "permission_class", "")
    if risk in _ROLLBACK_TRIGGER_TIERS or permission in _ROLLBACK_TRIGGER_TIERS:
        if not _is_nonempty_str(token.rollback_ref) or token.rollback_ref != request.rollback_ref:
            return _deny("DENY_NO_ROLLBACK", "rollback_ref required and must match request")

    # R4 3.4: the basis hash is RECOMPUTED from the request's six fields, never shape-trusted.
    expected_basis = approval_basis_hash(
        request.decision_basis_hash, request.effect_digest, request.generation_bundle_digest,
        request.rollback_digest, request.consumer_audience_hash, token.if06b_version)
    if token.approval_basis_hash != expected_basis:
        return _deny("DENY_APPROVAL_BASIS", "approval_basis_hash does not recompute")

    # R4: the context key generation, when it supplies one, must equal the token's; a caller
    # that pins a generation cannot be bypassed by a token that names another.
    if ctx.key_generation is not None and token.key_generation != ctx.key_generation:
        return _deny("DENY_TOKEN_INTEGRITY", "key_generation mismatch")

    if not _verify_signature(token, ctx):
        return _deny("DENY_TOKEN_INTEGRITY",
                     "Ed25519 signature not verified over RFC8785-framed bytes")

    ledger = ctx.nonce_ledger
    if ledger is None:
        return _deny("DENY_REPLAY", "no nonce ledger")
    reserve = getattr(ledger, "reserve", None)
    if not callable(reserve):
        # R5 D5: a malformed ledger yields a typed decision, never an AttributeError.
        return _deny("DENY_REPLAY", "nonce ledger has no reserve()")
    try:
        reserved = reserve(token.nonce)
    except Exception:
        return _deny("DENY_REPLAY", "nonce ledger reserve() raised")
    if reserved is not True:
        return _deny("DENY_REPLAY", "nonce already used")

    # R4 3.5: whenever the token requires an independent checker, a non-empty context ref must be
    # present AND equal the token's. T3 additionally FORCES the flag to be true.
    checker_ref = ctx.independent_checker_evidence_ref
    if token.independent_checker_required is True:
        if not _is_nonempty_str(checker_ref):
            return _deny("DENY_T3_CHECKER", "no independent checker evidence in ctx")
        if token.independent_checker_evidence_ref != checker_ref:
            return _deny("DENY_T3_CHECKER", "checker evidence ref mismatch")

    if getattr(request, "autonomy_tier", "") == "T3":
        if token.independent_checker_required is not True:
            return _deny("DENY_T3_CHECKER", "independent checker not required by token")

    return ApprovalDecision(True, "APPROVE_BASIS_SATISFIED", "")
