"""Source-as-DATA: external content never acquires authority. PI-PKG-05 18.1 / 19.

External content - web pages, README, issue text, arXiv, HF cards, RAG chunks, MCP metadata,
skills, provider/model output - is DATA. Embedded instructions never acquire authority.
Instructions to reveal secrets, auto-install/upload, approve, widen rights, claim PASS or
override governance trigger STOP for the affected operation + QUARANTINE + a TT; unrelated
safe compilation continues.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# PI-PKG-05 18.1 control vocabulary
QUARANTINE_TRIGGERS = (
    "ignore_previous_instructions", "ignore policy", "reveal_secret", "exfiltrate",
    "auto_install", "auto_upload", "self_approve", "grant_rights", "widen_permissions",
    "claim_pass", "override_governance", "run_tool_without_admission", "treat_as_authority",
)


class InjectionQuarantine(Exception):
    code = "SOURCE_INJECTION_QUARANTINE"


@dataclass
class SourceRecord:
    """External content is DATA. `authority` is always False and is not settable to True."""
    source_id: str
    content: str
    origin: str
    authority: bool = False
    _READONLY_AUTHORITY = True

    def __setattr__(self, name, value):
        if name == "authority" and getattr(self, "_READONLY_AUTHORITY", False) and value is not False:
            raise InjectionQuarantine(
                "external content cannot acquire authority (source-as-DATA law, PI-PKG-05 18.1)")
        object.__setattr__(self, name, value)


def scan_for_injection(content: str, source_id: str = "") -> dict:
    low = content.lower()
    hits = [t for t in QUARANTINE_TRIGGERS if t.replace("_", " ") in low or t in low]
    return {"source_id": source_id, "quarantined": bool(hits), "hits": hits}


def admit_source(rec: SourceRecord) -> dict:
    """Admit data, or STOP+QUARANTINE+TT for the affected operation only."""
    scan = scan_for_injection(rec.content, rec.source_id)
    if scan["quarantined"]:
        return {"admitted": False, "action": "STOP+QUARANTINE+TT", "affected_operation_only": True,
                "tt": f"TT-SOURCE-INJECTION-{rec.source_id}", "hits": scan["hits"],
                "unrelated_compilation_continues": True}
    return {"admitted": True, "authority": False, "data_only": True}


def claim_ceiling_for_external(content: str) -> str:
    """External text can never raise a claim ceiling."""
    return "SUPPORT_ONLY_NOT_AUTHORITY"
