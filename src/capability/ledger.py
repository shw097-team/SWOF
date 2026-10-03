"""W1 named-capability / workflow carry-forward ledger with REAL consumption receipts.

W1-EXT-005: "named capability ledgers consumed" is NOT satisfied by recording references.
This module consumes rows - binds the source locator, records the source disposition separately
from the current execution disposition, names the consumer, and proves a readback - or it
explicitly marks the row not-active with a reason. Silent omission or promotion is refused.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict

SOURCE_DISPOSITIONS = ("REUSE", "WRAP", "TRANSLATE", "ADAPT", "COMPOSE", "BUILD_MINIMUM",
                       "BUILD_NEW_EXCEPTION", "REUSE_AS_REFERENCE", "DEFERRED", "REJECTED")
EXEC_DISPOSITIONS = ("CONSUMED_ACTIVE", "CONSUMED_INACTIVE", "NOT_ACTIVE_WITH_REASON", "DEFERRED")


class LedgerDefect(Exception):
    code = "FAIL_NAMED_CARRY_FORWARD"


@dataclass
class NamedRow:
    row_id: str
    family: str                      # capability | workflow
    source_locator: str
    source_disposition: str
    consumer: str = ""               # the W1 seam that consumes it
    execution_disposition: str = ""
    readback_proof: str = ""         # what proves consumption
    not_active_reason: str = ""
    fallback_ref: str = ""
    provider_off_ref: str = ""

    def consume(self) -> dict:
        if self.source_disposition not in SOURCE_DISPOSITIONS:
            raise LedgerDefect(f"{self.row_id}: unknown source disposition {self.source_disposition!r}")
        # FIX-1: an EMPTY execution_disposition is silent omission - report it as such, and do not
        # let the generic membership error mask the real defect.
        if not self.execution_disposition:
            raise LedgerDefect(f"{self.row_id}: silent omission - no execution disposition recorded")
        if self.execution_disposition not in EXEC_DISPOSITIONS:
            raise LedgerDefect(f"{self.row_id}: execution_disposition must be one of {EXEC_DISPOSITIONS}")
        if self.execution_disposition == "CONSUMED_ACTIVE":
            if not self.consumer:
                raise LedgerDefect(f"{self.row_id}: CONSUMED_ACTIVE requires a named consumer")
            if not self.readback_proof:
                raise LedgerDefect(f"{self.row_id}: CONSUMED_ACTIVE requires a readback proof, "
                                   f"not merely a recorded reference")
        if self.execution_disposition == "NOT_ACTIVE_WITH_REASON" and not self.not_active_reason:
            raise LedgerDefect(f"{self.row_id}: NOT_ACTIVE_WITH_REASON requires a reason")
        # source disposition and execution disposition are separate axes; promotion is not implied
        return asdict(self)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)
                              .encode("utf-8")).hexdigest()


@dataclass
class LedgerConsumptionReceipt:
    schema: str = "SWOF-NAMED-CAPABILITY-CONSUMPTION/1"
    workorder_id: str = ""
    source_candidate_sha: str = ""
    rows: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    def build(self, rows: list) -> "LedgerConsumptionReceipt":
        consumed = []
        for r in rows:
            consumed.append(r.consume())
        self.rows = consumed
        self.counts = {
            "total": len(consumed),
            "consumed_active": sum(1 for r in consumed if r["execution_disposition"] == "CONSUMED_ACTIVE"),
            "consumed_inactive": sum(1 for r in consumed if r["execution_disposition"] == "CONSUMED_INACTIVE"),
            "not_active_with_reason": sum(1 for r in consumed
                                          if r["execution_disposition"] == "NOT_ACTIVE_WITH_REASON"),
            "deferred": sum(1 for r in consumed if r["execution_disposition"] == "DEFERRED"),
            "unconsumed": sum(1 for r in consumed if not r["execution_disposition"]),
        }
        if self.counts["unconsumed"]:
            raise LedgerDefect(f"{self.counts['unconsumed']} row(s) have no execution disposition "
                               f"(silent omission is refused)")
        return self

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.counts, sort_keys=True).encode("utf-8")).hexdigest()
