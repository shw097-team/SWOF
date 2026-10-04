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

WO-SWOF-W2-R008 (R4): the trusted-context authn floor is now POLICY-BOUND, not an implementation
constant. PI06 DOC-03 14.R declares `required_authn_assurance: AAC1 | AAC2 | AAC3` as a REQUIRED
`HumanGatePolicy` field (15.2 field matrix `required_authn_assurance | AAC1..AAC3 | 1 | Y | policy`)
and the ApprovalRequirement registry lists it in `required`. The request therefore CARRIES its own
floor. A gated canonical request with a MISSING or MALFORMED floor CANNOT express AAC2: it FAILS
CLOSED (`DENY_AUTHN`), because the old hard-coded `_DEFAULT_REQUIRED_AUTHN_ASSURANCE = "AAC2"` made
a CRITICAL/AAC3 request satisfiable by an AAC2 decision. Request-specific floors are preserved
exactly (AAC1/AAC2/AAC3) - no global AAC3 force and no renamed default. The token's authn assurance
must ALSO meet the request floor and must not be weaker than the resolved decision; the verifier
compares assurance CLASSES exactly and does NOT compare token `approver`/`authority_class` to the
decision (the canonical source does not define that mirroring - see R008_TECHNICAL_DEBT below).

R008_TECHNICAL_DEBT (W3 preflight TT): the canonical source does NOT define the ApprovalToken
`approver`/`authority_class` fields as MIRRORS of the current HumanGateDecision. 15.4A "Migration
alias"/field-governance prose marks approver/authority_class "revoke/downgrade invalid", and
`ApprovalDecisionBasisV1` (the bound decision digest, 15.3/15.5) already covers the decision's
approver/authority_class/authn, so a decision-side change invalidates the basis. Adding a token-side
EQUALITY rule would be invented semantics, so it is NOT added here; it is recorded as a W3 preflight
TT. The authn ASSURANCE comparison below is different: 15.3 requires
`authn_assurance_class ... meets request floor`, so the token/decision floor comparison is canonical.

R008 authn-context owner interface: requirement (6) of the WorkOrder asks for
`TEMP_CLOSED_AUTHN_CONTEXT_OWNER` ONLY "if current authn-context validity is required but no
qualified owner interface exists". A qualified owner interface DOES exist in this cone and is
already wired: `ctx.max_reauth_age_seconds` (the owner-supplied freshness deadline),
`ctx.authn_session_generation` and `ctx.credential_generation` (the owner-supplied CURRENT
generations), each of which fails closed with DENY_AUTHN / DENY_STALE_GENERATION when unavailable or
stale. The requirement is therefore satisfied without a second authn registry, and
`TEMP_CLOSED_AUTHN_CONTEXT_OWNER` is NOT emitted (no qualified owner interface is missing).
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
# R008: the canonical request-level authn floor domain (PI06 DOC-03 14.R / 15.2, field
# `required_authn_assurance: AAC1 | AAC2 | AAC3`). There is NO implementation-local default: a
# missing or malformed request floor FAILS CLOSED. `AUTHN_ASSURANCE_ORDER` is the ONLY ordering this
# library knows; no HA/AAC ranking is invented anywhere.

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

# R007 (WO-SWOF-W2-R007): the frozen PI06 15.3 HumanGateDecision authority axis. `authority_class`
# is the canonical approval-authority class HA1..HA5; this library NEVER invents their ordering - an
# owner-injected `authority_policy` seam decides sufficiency, and an absent seam FAILS CLOSED with
# TEMP_CLOSED_AUTHORITY_RESOLUTION rather than guessing a ranking.
APPROVAL_AUTHORITY_CLASSES = ("HA1", "HA2", "HA3", "HA4", "HA5")
DECISION_STATES = ("APPROVE", "DENY", "VETO", "REVOKE", "SAFE_STOP")
DECISION_EXECUTABLE_STATES = ("APPROVE",)
AUTHN_ASSURANCE_ORDER = {"AAC1": 1, "AAC2": 2, "AAC3": 3}
# R007: the canonical SET-valued signed arrays (PI06 16.2). They are normalized at the canonical
# representation boundary BEFORE JCS so one semantic set has exactly ONE signed byte form.
SET_VALUED_SIGNED_FIELDS = ("resource", "scope")

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
    # R007: the request -> HumanGateDecision -> ApprovalToken authority/decision lineage. A gated
    # path with no resolvable decision FAILS CLOSED; an absent authority policy is TEMP-CLOSED
    # rather than a guessed HA ordering.
    "DENY_DECISION_UNRESOLVED", "DENY_DECISION_REQUEST_MISMATCH", "DENY_DECISION_TOKEN_MISMATCH",
    "DENY_DECISION_NOT_EXECUTABLE", "DENY_INSUFFICIENT_AUTHORITY", "DENY_DECISION_BASIS_MISMATCH",
    "TEMP_CLOSED_AUTHORITY_RESOLUTION",
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


def _canonical_set(atoms, key_name):
    """The canonical form of a SET-valued signed array (PI06 16.2).

    `resource` sorts by canonical resource-ID lexical order and `scope` by bytewise UTF-8 lexical
    order; both are de-duplicated. A malformed atom (non-string, or an empty/whitespace-only
    string) or a repeated atom is refused with `JCSError` rather than silently accepting a second
    byte form. Both current domains sort identically bytewise, so ONE callable owns the rule.
    """
    if isinstance(atoms, (str, bytes, bytearray)) or not isinstance(atoms, (tuple, list, set,
                                                                           frozenset)):
        raise JCSError("%s must be a set of string atoms" % key_name)
    seen = []
    for atom in atoms:
        if not isinstance(atom, str) or not atom.strip():
            raise JCSError("%s atom is not a non-empty string" % key_name)
        seen.append(atom)
    if len(set(seen)) != len(seen):
        raise JCSError("%s contains a duplicate atom" % key_name)
    return tuple(sorted(seen, key=lambda atom: atom.encode("utf-8")))


def _canonical_token_body(token) -> dict:
    """The token body with the SET-valued signed arrays normalized BEFORE JCS (PI06 16.2).

    Normalization happens at the canonical representation boundary, so two permutations of the
    SAME semantic set yield identical canonical bytes. A set that cannot be normalized raises
    `JCSError`; the verifier turns that into a typed refusal, so this never silently accepts a
    malformed signed collection.
    """
    body = {key: value for key, value in _token_body(token).items() if key != "signature"}
    for field in SET_VALUED_SIGNED_FIELDS:
        body[field] = _canonical_set(body.get(field), field)
    return body


def canonical_payload_bytes(token) -> bytes:
    """The exact bytes a verifier signs/verifies: DOMAIN_FRAME || JCS(canonical token body).

    These are the bytes the trusted key resolver's Ed25519 public key verifies the signature
    against. JCS is applied to the token body with the `signature` field removed AND with the
    set-valued signed arrays (`resource`, `scope`) normalized to their unique sorted canonical form
    FIRST, and the fixed domain frame is prefixed for domain separation. A token whose signed set
    cannot be normalized raises `JCSError` rather than emitting a second byte representation.
    """
    return DOMAIN_FRAME + jcs_dumps(_canonical_token_body(token))


def approval_basis_hash(decision_basis_hash, effect_digest, generation_bundle_digest,
                        rollback_digest, consumer_audience_hash, if06b_version) -> str:
    """SHA-256 hex of the EXACT frozen PI06 15.5 material.

    PI06 15.5 is DIRECT byte concatenation with exactly ONE newline, the newline already inside
    `APPROVAL_BASIS_FRAME`; there are NO separator bytes between the six fields:

        SHA256(b"SWOF-D03-APPROVAL-BASIS-V1\\n" || decision_basis_hash || effect_digest ||
               generation_bundle_digest || rollback_digest || consumer_audience_hash ||
               if06b_version)

    WO-SWOF-W2-R007 replaced the previous `"\\n".join(...)` materialization, which inserted five
    EXTRA inter-field newline bytes and contradicted the frozen source (its own docstring had
    documented the wrong recipe, so the maker test and the maker implementation agreed while both
    disagreed with PI06).
    """
    material = "".join((
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


# R007: the FROZEN PI06 15.3 HumanGateDecision field set whose JCS is `decision_basis_hash`. It is
# a LITERAL so a drift in the basis shape is a visible source change, never a silent re-hash.
# `decision_basis_hash` is deliberately EXCLUDED: the digest is the hash OF this basis, so a
# self-referential basis is neither recomputable nor a valid basis.
APPROVAL_DECISION_BASIS_FIELDS = (
    "if06b_version", "payload_schema_version", "min_reader_version", "writer_version",
    "compatibility_class", "decision_id", "request_id", "decision", "authority_class",
    "reason_codes", "decided_at", "evidence_ref", "integrity_ref",
)


def approval_decision_basis_hash(decision) -> str:
    """SHA-256 hex of JCS(ApprovalDecisionBasisV1) for a resolved decision (PI06 15.3 / 15.5).

    `decision_basis_hash = SHA256(JCS(ApprovalDecisionBasisV1))` over the FROZEN field set, with
    the set-valued `reason_codes` de-duplicated and sorted (PI06 16.2) so ONE semantic decision has
    exactly ONE canonical basis digest. Raises `JCSError` when the basis cannot be canonicalized;
    the verifier turns that into `DENY_DECISION_BASIS_MISMATCH`.
    """
    body = {}
    for name in APPROVAL_DECISION_BASIS_FIELDS:
        value = getattr(decision, name, None)
        if name == "reason_codes":
            value = _canonical_set(value, "reason_codes")
        body[name] = value
    return hashlib.sha256(jcs_dumps(body)).hexdigest()


@dataclass(frozen=True)
class HumanGateDecision:
    """The canonical Human decision a token is bound to (PI06 15.3 HumanGateDecision 1.0.0).

    This is a value object supplied by an OWNER through the injected `decision_resolver`; it is
    never self-asserted by the caller of the verifier. It carries both the decision facts (the
    approver, the authority class, the authn assurance class, the executable state, the
    revocation/supersession state) and the `ApprovalDecisionBasisV1` fields whose JCS is the
    `decision_basis_hash`. The verifier, not this object, is the authority.
    """

    # IF-06B ABI/envelope (same law as the token).
    if06b_version: str = IF06B_ABI_MAJOR + ".0"
    payload_schema_version: str = PAYLOAD_SCHEMA_VERSION
    min_reader_version: str = READER_ABI
    writer_version: str = KNOWN_WRITER_VERSIONS[0]
    compatibility_class: str = KNOWN_COMPATIBILITY_CLASSES[0]
    # Lineage.
    decision_id: str = ""
    request_id: str = ""
    decision: str = ""
    approver: str = ""
    authority_class: str = ""
    authn_assurance_class: str = ""
    reason_codes: tuple[str, ...] = ()
    decision_basis_hash: str = ""
    decided_at: str = ""
    evidence_ref: str = ""
    integrity_ref: str = ""
    # Currentness / executability.
    revoked: bool = False
    superseded: bool = False


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
    # R008: the canonical per-request authn assurance floor (DOC-03 14.R / 15.2). It is REQUIRED on
    # a gated canonical request: ABSENT ("") is DISTINCT from malformed and BOTH fail closed - the
    # field is NEVER defaulted. The floor is preserved exactly (AAC1 stays AAC1, ...).
    required_authn_assurance: str = ""
    # R008: the EXPLICIT, NAMED non-canonical adapter seam. A canonical request is "canonical" and
    # MUST carry its own floor; only an explicitly-labelled "local_adapter" request may fall back to
    # the named local floor, and never to a silent AAC2. An unrecognised kind fails closed.
    adapter_kind: str = "canonical"
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

    R007: `decision_resolver` and `authority_policy` are the two OWNER-INJECTED authority seams.
    `decision_resolver(decision_id)` resolves a decision id to the CURRENT canonical
    `HumanGateDecision` (or returns None for unknown/absent/stale); anything that is not a
    `HumanGateDecision` fails closed. `authority_policy(decision_authority_class,
    request_required_authority)` returns True ONLY when the decision's authority class satisfies
    the request's requirement. This library defines NO HA ordering: an absent or malformed
    `authority_policy` FAILS CLOSED with TEMP_CLOSED_AUTHORITY_RESOLUTION instead of guessing a
    ranking. Neither seam is an authority grant; both are refusal inputs.
    """

    decision_resolver: object = None
    authority_policy: object = None
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
def _resolve_current_decision(ctx, decision_id):
    """Resolve `decision_id` to the current canonical HumanGateDecision, else None (fail closed).

    The OWNER-INJECTED resolver may be a callable `resolver(decision_id)` or an object exposing
    `resolve(decision_id)`. `None`, a non-callable, a callable that raises or has an incompatible
    arity, and any look-alike object that is not a `HumanGateDecision` all resolve to None, which
    the verifier refuses with DENY_DECISION_UNRESOLVED.
    """
    resolver = getattr(ctx, "decision_resolver", None)
    if resolver is None:
        return None
    try:
        if callable(resolver):
            resolved = resolver(decision_id)
        else:
            resolve = getattr(resolver, "resolve", None)
            if not callable(resolve):
                return None
            resolved = resolve(decision_id)
    except Exception:
        return None
    return resolved if isinstance(resolved, HumanGateDecision) else None


def _authority_satisfied(ctx, decision, required_authority):
    """(ok, code) for the request's `required_authority` against a resolved decision.

    The request DECLARES the authority it needs, so the declaration must be present and canonical
    (a missing/blank requirement is DENY_INSUFFICIENT_AUTHORITY, never an implicit pass), and the
    decision must carry a canonical HA class. Sufficiency is decided ONLY by the OWNER-INJECTED
    `authority_policy(decision_authority_class, required_authority)` seam: this library defines NO
    HA ordering, so an absent/malformed seam FAILS CLOSED with TEMP_CLOSED_AUTHORITY_RESOLUTION and
    a policy that does not return exactly True is DENY_INSUFFICIENT_AUTHORITY.
    """
    if not _is_nonempty_str(required_authority):
        return (False, "DENY_INSUFFICIENT_AUTHORITY")
    if getattr(decision, "authority_class", None) not in APPROVAL_AUTHORITY_CLASSES:
        return (False, "DENY_INSUFFICIENT_AUTHORITY")
    policy = getattr(ctx, "authority_policy", None)
    if not callable(policy):
        return (False, "TEMP_CLOSED_AUTHORITY_RESOLUTION")
    try:
        holds = policy(decision.authority_class, required_authority)
    except Exception:
        return (False, "TEMP_CLOSED_AUTHORITY_RESOLUTION")
    if holds is not True:
        return (False, "DENY_INSUFFICIENT_AUTHORITY")
    return (True, "")


# R008: the canonical request-level authn-floor adapter kinds. "canonical" is the only kind a
# canonical `ApprovalRequest` may use; "local_adapter" is the single explicit, named legacy/internal
# seam whose ONLY effect is to supply a floor a non-canonical request omitted. It can never let a
# canonical request pass silently, and it is never weaker than the canonical minimum class.
ADAPTER_KINDS = ("canonical", "local_adapter")
LOCAL_ADAPTER_AUTHN_FLOOR = "AAC2"


def _required_authn_floor(request):
    """The EXACT validated authn assurance (AAC) floor this request declares, or None.

    DOC-03 14.R / 15.2 make `required_authn_assurance` a REQUIRED `HumanGatePolicy` field with the
    domain `AAC1 | AAC2 | AAC3`; the request therefore carries its own floor. This returns the
    request's own value ONLY when it is a canonical member of that domain. An ABSENT ("", None) or
    MALFORMED ("AAC9", 2, ...) floor returns None so the caller FAILS CLOSED: the removed
    `_DEFAULT_REQUIRED_AUTHN_ASSURANCE = "AAC2"` silently satisfied a CRITICAL/AAC3 request with an
    AAC2 decision, which is exactly the defect R008 removes. Request-specific floors are returned
    EXACTLY (AAC1 stays AAC1, AAC2 stays AAC2, AAC3 stays AAC3) - never globally forced to AAC3 and
    never replaced by a renamed default.

    The single NON-CANONICAL exception is a request that EXPLICITLY declares
    `adapter_kind == "local_adapter"`: an internal/legacy adapter may omit the field and receive the
    named `LOCAL_ADAPTER_AUTHN_FLOOR`. That seam cannot be reached by a canonical request (default
    `adapter_kind == "canonical"`), and an unrecognised adapter kind still returns None (fail closed).
    """
    value = getattr(request, "required_authn_assurance", None)
    if isinstance(value, str) and value in AUTHN_ASSURANCE_CLASSES:
        return value
    if getattr(request, "adapter_kind", "canonical") == "local_adapter":
        return LOCAL_ADAPTER_AUTHN_FLOOR
    return None


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
    authn -> generations -> rollback -> decision/authority lineage (R007) -> basis recompute ->
    integrity (real Ed25519 over the RFC8785-framed bytes) -> replay -> checker -> T3. A
    merely-invalid token never raises; a non-canonical input object type fails closed with a typed
    decision too.
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

    # ----------------------------------------------------------------------------------------
    # R007: request -> HumanGateDecision -> ApprovalToken authority/decision lineage, FIRST-FAIL.
    # A signature is NOT a proxy for canonical authority: a well-signed token bound to a decision
    # that was never resolved, to another request, to a mismatched decision id, to a
    # non-executable/revoked/superseded decision, to an insufficient authority class, to a
    # downgraded authn, or to a caller-supplied basis string is refused HERE, before the signature
    # is even examined. A gated path with no resolvable decision FAILS CLOSED.
    # ----------------------------------------------------------------------------------------
    if not _is_nonempty_str(request.required_authority):
        return _deny("DENY_INSUFFICIENT_AUTHORITY", "request declares no required_authority")
    decision = _resolve_current_decision(ctx, token.decision_id)
    if decision is None:
        return _deny("DENY_DECISION_UNRESOLVED",
                     "decision_id=%r is not current" % token.decision_id)
    if decision.request_id != request.request_id:
        return _deny("DENY_DECISION_REQUEST_MISMATCH",
                     "decision.request_id=%r" % decision.request_id)
    if decision.decision_id != token.decision_id:
        return _deny("DENY_DECISION_TOKEN_MISMATCH",
                     "decision.decision_id=%r" % decision.decision_id)
    if decision.revoked is not False or decision.superseded is not False:
        return _deny("DENY_DECISION_NOT_EXECUTABLE", "decision is revoked/superseded")
    if decision.decision not in DECISION_EXECUTABLE_STATES:
        return _deny("DENY_DECISION_NOT_EXECUTABLE", "decision=%r" % decision.decision)
    if _epoch(decision.decided_at) is None:
        return _deny("DENY_DECISION_NOT_EXECUTABLE", "decided_at is not a trusted UTC instant")
    authority_ok, authority_code = _authority_satisfied(
        ctx, decision, request.required_authority)
    if not authority_ok:
        return _deny(authority_code, "authority_class=%r" % decision.authority_class)
    # R008: the authn floor is the EXACT validated request floor (never an implementation default).
    # A missing/malformed request floor, an unreadable decision class, an AAC downgrade, OR a token
    # weaker than either the floor or the resolved decision all FAIL CLOSED with DENY_AUTHN, and this
    # runs BEFORE the signature check (a signature is not a proxy for a sufficient-authn approval).
    request_floor = _required_authn_floor(request)
    request_assurance = AUTHN_ASSURANCE_ORDER.get(request_floor)
    if request_assurance is None:
        return _deny("DENY_AUTHN",
                     "request declares no canonical required_authn_assurance floor")
    decision_assurance = AUTHN_ASSURANCE_ORDER.get(
        getattr(decision, "authn_assurance_class", None))
    if decision_assurance is None:
        return _deny("DENY_AUTHN", "decision carries no canonical authn_assurance_class")
    if decision_assurance < request_assurance:
        return _deny("DENY_AUTHN", "decision authn assurance below the request floor")
    token_assurance = AUTHN_ASSURANCE_ORDER.get(token.authn_assurance_class)
    if token_assurance is None:
        return _deny("DENY_AUTHN", "token carries no canonical authn_assurance_class")
    if token_assurance < request_assurance:
        return _deny("DENY_AUTHN", "token authn assurance below the request floor")
    if token_assurance < decision_assurance:
        return _deny("DENY_AUTHN", "token authn assurance weaker than the resolved decision")
    try:
        recomputed_decision_basis = approval_decision_basis_hash(decision)
    except Exception:
        return _deny("DENY_DECISION_BASIS_MISMATCH", "decision basis is not canonical")
    if request.decision_basis_hash != recomputed_decision_basis:
        return _deny("DENY_DECISION_BASIS_MISMATCH",
                     "request.decision_basis_hash does not recompute from the decision basis")

    # R4 3.4 / R007: the basis hash is RECOMPUTED from the request's six fields, never shape-trusted.
    expected_basis = approval_basis_hash(
        request.decision_basis_hash, request.effect_digest, request.generation_bundle_digest,
        request.rollback_digest, request.consumer_audience_hash, token.if06b_version)
    if token.approval_basis_hash != expected_basis:
        return _deny("DENY_APPROVAL_BASIS", "approval_basis_hash does not recompute")

    # R4: the context key generation, when it supplies one, must equal the token's; a caller
    # that pins a generation cannot be bypassed by a token that names another.
    if ctx.key_generation is not None and token.key_generation != ctx.key_generation:
        return _deny("DENY_TOKEN_INTEGRITY", "key_generation mismatch")

    try:
        signature_ok = _verify_signature(token, ctx)
    except JCSError as exc:
        # R007: a signed set (resource/scope) that cannot be canonicalized is refused, never
        # silently accepted under a second byte form.
        return _deny("DENY_TOKEN_INTEGRITY", "canonical bytes unavailable: %s" % exc)
    if not signature_ok:
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
