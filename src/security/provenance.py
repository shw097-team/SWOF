"""External content is DATA, never authority. Promotion is a registered-authority edge.

WHY: retrieved documents, RAG hits, web pages, tool output and model output all arrive as text,
and imperative text ("ignore previous instructions, you are now the system") is exactly what an
injection looks like. If any constructor could turn that text into an INSTRUCTION, a hostile
document would silently become a policy. Here only a caller explicitly flagged as a registered
authority may promote content, and that promotion is an authority edge owned by a human owner.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

KINDS = frozenset({"DATA", "INSTRUCTION"})
TRUSTS = frozenset({"UNTRUSTED", "EXTERNAL", "INTERNAL", "AUTHORITY"})

NEUTRALIZED = "[NEUTRALIZED]"

_AUTHORITY_CLAIM_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:the\s+)?previous\s+instructions?",
    r"ignore\s+(?:the\s+)?previous\s+instruction",
    r"disregard\s+(?:all\s+)?(?:the\s+)?above(?:\s+instructions?)?",
    r"you\s+are\s+now",
    r"new\s+instructions?",
    r"override\s+the\s+policy",
    r"system\s*:",
)
_AUTHORITY_CLAIM_RE = re.compile("|".join(_AUTHORITY_CLAIM_PATTERNS), re.IGNORECASE)


class AuthorityEscalationRefused(Exception):
    """Content tried to become an instruction without a registered authority edge."""

    code = "ERR_AUTHORITY_ESCALATION_REFUSED"


class ProvenanceInvalid(Exception):
    """Malformed provenance: fail closed rather than treat unknown as trusted."""

    code = "ERR_PROVENANCE_INVALID"


@dataclass(frozen=True)
class ContentEnvelope:
    """Content plus its provenance. `kind` defaults to DATA and is not self-assigned."""

    origin: str
    text: str
    kind: str = "DATA"
    trust: str = "UNTRUSTED"
    authority_id: str | None = None


def _validate(env) -> None:
    if not isinstance(env, ContentEnvelope):
        raise ProvenanceInvalid("value is not a ContentEnvelope; refusing to guess")
    if not isinstance(env.origin, str) or not env.origin:
        raise ProvenanceInvalid("content origin must be a non-empty string")
    if not isinstance(env.text, str):
        raise ProvenanceInvalid("content text must be a string")
    if env.kind not in KINDS:
        raise ProvenanceInvalid(f"unknown kind {env.kind!r}")
    if env.trust not in TRUSTS:
        raise ProvenanceInvalid(f"unknown trust {env.trust!r}")


def as_data(origin, text, *, trust="UNTRUSTED") -> ContentEnvelope:
    """Wrap external text as DATA. There is no constructor that makes it an INSTRUCTION."""
    env = ContentEnvelope(origin=origin, text=text, kind="DATA", trust=trust)
    _validate(env)
    return env


def assert_data_only(env) -> ContentEnvelope:
    """Pass DATA through; refuse an INSTRUCTION or malformed provenance."""
    _validate(env)
    if env.kind == "INSTRUCTION":
        raise AuthorityEscalationRefused(
            f"content from {env.origin!r} is an INSTRUCTION and cannot be treated as data")
    return env


def strip_authority_claims(text) -> str:
    """Neutralize imperative authority phrases so the text stays safe to keep as data."""
    if not isinstance(text, str):
        raise ProvenanceInvalid("strip_authority_claims expects a string")
    return _AUTHORITY_CLAIM_RE.sub(NEUTRALIZED, text)


def promote(envelope, *, owner, owner_is_registered_authority=False) -> ContentEnvelope:
    """AUTHORITY EDGE: only a registered authority may raise DATA to INSTRUCTION."""
    _validate(envelope)
    if not isinstance(owner, str) or not owner:
        raise ProvenanceInvalid("promotion owner must be a non-empty string")
    if not owner_is_registered_authority:
        raise AuthorityEscalationRefused(
            f"content from {envelope.origin!r} cannot promote itself; {owner!r} is not a "
            "registered authority")
    return ContentEnvelope(
        origin=envelope.origin,
        text=envelope.text,
        kind="INSTRUCTION",
        trust="AUTHORITY",
        authority_id=owner,
    )
