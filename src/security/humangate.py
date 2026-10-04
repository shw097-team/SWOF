"""Typed, exact-bound human approval tokens at the existing HumanGate seam.

WHY: a HumanGate that accepts any non-empty string is a syntactic gate, not an authority gate -
"approved" typed by the actor who wants the action is indistinguishable from a real approval, so
the gate refuses nothing. This module makes the approval a typed value object bound exactly to the
request it approves and to the currentness inputs at commit time, and makes the verifier the only
authority. It adds no cryptography of its own: it DEFINES the canonical bytes a real verifier
signs, and it delegates the actual signature check to an injected trusted key registry
(VERIFIER). The registry is the only place a signature may be judged; this library never claims
to have verified a signature. It FAILS CLOSED when the registry is absent, refuses, or raises.

This is a refusal mechanism, not a second authority system. It grants nothing, produces no
Product/Semantic truth, and never reads the wall clock: `commit_time` and every generation are
explicit trusted inputs supplied by the caller.

W2 repair WO-SWOF-W2-R003 (schema fidelity): the runtime type must be STRICTER OR EQUAL to the
canonical registry, never broader. The token therefore carries the IF-06B ABI/envelope fields
(`if06b_version`, `payload_schema_version`, `min_reader_version`, `writer_version`,
`compatibility_class`, `evidence_link`) that the canonical ApprovalToken 1.0.0 schema requires, and
the verifier refuses an unsupported ABI major (`IF06B_VERSION_UNSUPPORTED`) or an unreadable
envelope (`DENY_TOKEN_SCHEMA`) before any authority check runs.
"""
from __future__ import annotations

import base64
import json
import re
import threading
from dataclasses import asdict, dataclass, field
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

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

_DIGEST_FIELDS = ("subject_hash", "effect_digest", "consumer_audience_hash", "approval_basis_hash")

_REQUIRED_TEXT_FIELDS = (
    "token_id", "request_id", "decision_id", "subject", "semantic_version", "actor", "operation",
    "target_system", "environment", "purpose_ref", "data_class", "approver", "authority_class",
    "approver_authn_context_ref", "reauthenticated_at", "issued_at", "expires_at", "nonce",
    "token_state", "consumer", "integrity_profile_id", "issuer_id", "key_id",
)

_GENERATION_FIELDS = ("authn_session_generation", "credential_generation", "key_generation")

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

_ROLLBACK_TRIGGER_TIERS = ("P3", "P4", "P5")


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
    target_system: str = ""
    resource: tuple[str, ...] = ()
    environment: str = ""
    purpose_ref: str = ""
    scope: tuple[str, ...] = ()
    data_class: str = ""
    effect_digest: str = ""
    consumer_audience_hash: str = ""
    effect_risk_tier: str = ""
    permission_class: str = ""
    autonomy_tier: str = ""
    required_authority: str = ""
    rollback_ref: str = ""
    independent_checker_required: bool = False


@dataclass(frozen=True)
class VerificationContext:
    """The trusted current-at-commit inputs. Nothing here is read from the wall clock.

    `trusted_key_registry` is a CALLABLE VERIFIER, not a key-existence lookup. The verifier is the
    ONLY place a signature may be judged: it is called as
    `registry(payload_bytes, signature, issuer_id, key_id, key_generation)` where `payload_bytes`
    is `canonical_payload_bytes(token)`, and it MUST recompute a signature over those bytes with
    the named key (or verify the signature against a trust store) and return EXACTLY `True` to
    accept. Anything that is not exactly `True` - `None`, `False`, `0`, a truthy object - is
    refused, and a verifier that raises or has an incompatible arity is refused. A registry that
    only checks key existence and returns `True` without consulting `payload_bytes` is NOT a valid
    verifier: it accepts forgeries. That is a contract violation by the integrator; the library
    defers to the registry by design and therefore inherits exactly the strength of the verifier
    it is given.
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


def canonical_payload_bytes(token) -> bytes:
    """The bytes a real verifier signs: UTF-8 JSON of the token EXCLUDING `signature`, with keys
    sorted and separators (',', ':') - a deterministic canonical form.

    The library performs NO cryptography; it only defines the bytes so a real verifier can
    recompute them. Tuples serialise as JSON arrays, which is fine as long as it is deterministic.
    """
    body = {key: value for key, value in asdict(token).items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
    DENY_TOKEN_SCHEMA family so no downstream consumer needs a new code. Every unknown or
    unreadable envelope value is refused, never defaulted.
    """
    abi = getattr(token, "if06b_version", None)
    if not isinstance(abi, str) or not abi:
        return "IF06B_VERSION_UNSUPPORTED"
    if abi.split(".")[0] != IF06B_ABI_MAJOR:
        return "IF06B_VERSION_UNSUPPORTED"
    if token.payload_schema_version != PAYLOAD_SCHEMA_VERSION:
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
    """Exact binding of the token to the request (TOK-INV-002)."""
    errors = []
    scalar_fields = (
        "subject", "subject_hash", "semantic_version", "actor", "operation", "target_system",
        "environment", "purpose_ref", "data_class", "effect_digest", "consumer_audience_hash",
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


def verify_approval_token(token, request, ctx) -> ApprovalDecision:
    """First-fail, deterministic verification of an exact-bound human approval token.

    Order: non-canonical token -> shape -> token_state -> exact binding -> audience -> time ->
    false authority (incl. approver != actor) -> authn -> generations -> rollback -> integrity
    (the injected registry VERIFIER recomputes over canonical_payload_bytes) -> replay -> T3.
    A merely-invalid token never raises; a non-canonical input object type does.
    """
    if not isinstance(token, ApprovalToken):
        return _deny("NOT_A_CANONICAL_APPROVAL_TOKEN", "token is not an ApprovalToken")
    if not isinstance(request, ApprovalRequest) or not isinstance(ctx, VerificationContext):
        raise ValueError("NOT_A_CANONICAL_APPROVAL_TOKEN: request/ctx must be canonical objects")

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

    expected_audience = ctx.expected_consumer_audience_hash
    if expected_audience is not None and expected_audience != token.consumer_audience_hash:
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
        return _deny("DENY_FALSE_AUTHORITY", "approver=%r is not a human principal ref" % token.approver)
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

    if ctx.trusted_key_registry is None:
        return _deny("DENY_TOKEN_INTEGRITY", "no trusted key registry")
    if ctx.key_generation is not None and token.key_generation != ctx.key_generation:
        return _deny("DENY_TOKEN_INTEGRITY", "key_generation mismatch")
    payload = canonical_payload_bytes(token)
    try:
        verified = ctx.trusted_key_registry(payload, token.signature, token.issuer_id,
                                            token.key_id, token.key_generation)
    except TypeError:  # an incompatible arity cannot answer -> fail closed
        return _deny("DENY_TOKEN_INTEGRITY", "registry has incompatible arity")
    except Exception as exc:  # a registry that cannot answer is unavailable -> fail closed
        return _deny("DENY_TOKEN_INTEGRITY", "registry raised %s" % type(exc).__name__)
    if verified is not True:
        return _deny("DENY_TOKEN_INTEGRITY", "signature not verified")

    if ctx.nonce_ledger is None:
        return _deny("DENY_REPLAY", "no nonce ledger")
    if ctx.nonce_ledger.reserve(token.nonce) is not True:
        return _deny("DENY_REPLAY", "nonce already used")

    if getattr(request, "autonomy_tier", "") == "T3":
        checker_ref = ctx.independent_checker_evidence_ref
        if token.independent_checker_required is not True:
            return _deny("DENY_T3_CHECKER", "independent checker not required by token")
        if not _is_nonempty_str(checker_ref):
            return _deny("DENY_T3_CHECKER", "no independent checker evidence in ctx")
        if token.independent_checker_evidence_ref != checker_ref:
            return _deny("DENY_T3_CHECKER", "checker evidence ref mismatch")

    return ApprovalDecision(True, "APPROVE_BASIS_SATISFIED", "")


def _base64url_signature(seed: bytes = b"SWOF-HG-INTEGRITY-001") -> str:
    """A deterministic 86-char base64url shape fixture. Not a real signature; shape only."""
    digest = b""
    block = seed
    while len(digest) < 64:
        digest += block
        block = block[::-1] + b"."
    encoded = base64.urlsafe_b64encode(digest[:64]).decode("ascii").rstrip("=")
    return (encoded + "A" * 86)[:86]