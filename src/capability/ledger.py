"""W1 named-capability / workflow carry-forward ledger with REAL consumption receipts.

W1-EXT-005: "named capability ledgers consumed" is NOT satisfied by recording references.
R2-002  : the earlier version validated `source_disposition` against the Search-Before-Build
          ADMISSION LADDER (REUSE/WRAP/.../BUILD_NEW_EXCEPTION), which is a DIFFERENT axis. That
          made `source_disposition = "DEFERRED"` type-legal and let a canonical source state such
          as `SELECTED_FOR_PREDEV` be collapsed into an execution label. Two independent axes are
          therefore modelled explicitly here:

            source_disposition     - canonical Pre-Implementation terminal disposition copied
                                     VERBATIM from the source row (PI-PKG-05 r2 §19.1 / terminal
                                     disposition sets). This is NOT a runtime install/binding claim
                                     and NOT the build ladder.
            execution_disposition  - current W1 execution state (consumed / not active / deferred).

          Fidelity is enforced mechanically, not by convention:
            * the source token must belong to the retrieved canonical registry, else the row is
              typed TEMP_CLOSED_REGISTRY_ROW (fail closed; vocabulary is never invented);
            * an execution-only label can NEVER be used as a source disposition;
            * the canonical token must appear VERBATIM in `canonical_source_text`, which is the
              quoted source line - so relabelling the field while quoting the real row fails.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------------------------
# Axis A - canonical SOURCE-side Pre-Implementation terminal dispositions.
# Every token below was retrieved verbatim from the current source corpus; the value records the
# exact locator it was read from. Do NOT add tokens by guessing: an unretrieved token must fail
# closed as TEMP_CLOSED_REGISTRY_ROW and be raised as a typed TT for that row.
# ---------------------------------------------------------------------------------------------
_P05 = "PI-PKG-05_2026-09-14_r2_FULL_REPAIR.md"
SOURCE_DISPOSITION_REGISTRY = {
    "SELECTED_FOR_PREDEV": f"{_P05} §19.1 L3595 (OPA/Rego OPA_POLICY_EVAL)",
    "ADOPT_WITH_ADAPTER": f"{_P05} §19.1 L3597 (OpenLineage OL_LINEAGE_ADAPTER)",
    "ADOPT_WITH_ADAPTER_CONDITIONAL_ON_DOC09": f"{_P05} §19.1 L3599 (OpenFGA FGA_RELATIONSHIP_AUTHZ)",
    "REJECTED_FOR_PRIMARY_POLICY_SLOT": f"{_P05} §19.1 L3603 (Cedar)",
    "REUSE_AS_REFERENCE": f"{_P05} §19.1 L3601/L3605 (W3C PROV-O / Hugging Face cards)",
    "TEMP_CLOSED_PREDEV_EXACT_SERVER_PIN": f"{_P05} §19.1 L3599 (OpenFGA exact pin, TEMP_CLOSED)",
    "SELECTED_FOR_PREDEV_QUALIFICATION": f"{_P05} L10618 (terminal disposition set)",
    "CONSTRUCTION_ONLY": f"{_P05} L10618 (terminal disposition set)",
    "TRANSLATE": f"{_P05} L10618 (terminal disposition set)",
    "REFERENCE_ONLY": f"{_P05} L10618 (terminal disposition set)",
    "METHOD_DONOR_ONLY": f"{_P05} L10618 (terminal disposition set)",
    "SECURITY_SUPPORT_ONLY": f"{_P05} L10618 (terminal disposition set)",
    "QUARANTINE/EVAL_ONLY": f"{_P05} L10618 (terminal disposition set)",
    "REJECT": f"{_P05} L10618 (terminal disposition set)",
}
# L10618 admits the open family `TEMP_CLOSED_*`; accept that prefix, never an arbitrary token.
SOURCE_DISPOSITION_PREFIXES = ("TEMP_CLOSED_",)

# Axis B - current W1 execution state. Values here are NOT source dispositions.
EXEC_DISPOSITIONS = ("CONSUMED_ACTIVE", "CONSUMED_INACTIVE", "NOT_ACTIVE_WITH_REASON", "DEFERRED")

# Axis C - the Search-Before-Build admission ladder (W1-003, src/admission). Kept explicitly
# separate so it can never be mistaken for a source-disposition vocabulary again.
ADMISSION_LADDER_DISPOSITIONS = ("REUSE", "WRAP", "TRANSLATE", "ADAPT", "COMPOSE",
                                 "BUILD_MINIMUM", "BUILD_NEW_EXCEPTION", "REUSE_AS_REFERENCE")

# A label that belongs to the execution axis may never be written as a source disposition.
EXECUTION_ONLY_LABELS = frozenset(EXEC_DISPOSITIONS)

# The L10618 terminal-disposition set, quoted verbatim from the source. A row whose disposition is
# ASSIGNED (not literally stated for that row) may only use a token from this set, and must say so.
TERMINAL_DISPOSITION_SET = ("SELECTED_FOR_PREDEV_QUALIFICATION", "CONSTRUCTION_ONLY", "TRANSLATE",
                            "REFERENCE_ONLY", "METHOD_DONOR_ONLY", "SECURITY_SUPPORT_ONLY",
                            "QUARANTINE/EVAL_ONLY", "REJECT")

# How a row's source disposition was obtained - recorded, never assumed:
#   SOURCE_VERBATIM        the token is literally present in the quoted source line (e.g. §19.1)
#   ASSIGNED_TERMINAL_SET  the source does not state a disposition for this row; the token is
#                          assigned from the terminal set and the quote proves the obligation
DISPOSITION_EVIDENCE_KINDS = ("SOURCE_VERBATIM", "ASSIGNED_TERMINAL_SET")


class LedgerDefect(Exception):
    code = "FAIL_NAMED_CARRY_FORWARD"


class UnresolvedSourceDisposition(LedgerDefect):
    """The row's source token is not in the retrieved canonical registry -> typed TT, fail closed."""
    code = "TEMP_CLOSED_REGISTRY_ROW"


class SourceDispositionCoercion(LedgerDefect):
    """An execution-only label was used as a source disposition."""
    code = "FAIL_NAMED_CARRY_FORWARD"


class SourceDispositionNotVerbatim(LedgerDefect):
    """The canonical token does not appear verbatim in the quoted source text."""
    code = "FAIL_NAMED_CARRY_FORWARD"


@dataclass
class NamedRow:
    row_id: str
    family: str                      # capability | workflow
    source_locator: str
    source_disposition: str          # Axis A - canonical, verbatim
    canonical_source_text: str = ""  # the quoted source line the token was read from
    disposition_evidence: str = "SOURCE_VERBATIM"   # how the token was obtained (see above)
    consumer: str = ""               # the W1 seam that consumes it
    execution_disposition: str = ""  # Axis B
    readback_proof: str = ""         # what proves consumption
    not_active_reason: str = ""
    fallback_ref: str = ""
    provider_off_ref: str = ""

    # -- Axis A guards -------------------------------------------------------------------------
    def _assert_source_axis(self) -> None:
        if not self.source_disposition:
            raise UnresolvedSourceDisposition(
                f"{self.row_id}: no source_disposition recorded (silent omission refused)")
        if self.source_disposition in EXECUTION_ONLY_LABELS:
            raise SourceDispositionCoercion(
                f"{self.row_id}: {self.source_disposition!r} is an EXECUTION-axis label and may "
                f"never be written as a source_disposition")
        known = (self.source_disposition in SOURCE_DISPOSITION_REGISTRY
                 or self.source_disposition.startswith(SOURCE_DISPOSITION_PREFIXES))
        if not known:
            raise UnresolvedSourceDisposition(
                f"{self.row_id}: source_disposition {self.source_disposition!r} is not in the "
                f"retrieved canonical registry - raise TEMP_CLOSED_REGISTRY_ROW for this row "
                f"rather than inventing vocabulary")
        if not self.canonical_source_text:
            raise SourceDispositionNotVerbatim(
                f"{self.row_id}: canonical_source_text is required to prove the source token was "
                f"read verbatim")
        if self.disposition_evidence not in DISPOSITION_EVIDENCE_KINDS:
            raise LedgerDefect(
                f"{self.row_id}: disposition_evidence must be one of {DISPOSITION_EVIDENCE_KINDS}")
        if self.disposition_evidence == "SOURCE_VERBATIM":
            # the canonical row states the disposition itself - the token must be in the quote
            if self.source_disposition not in self.canonical_source_text:
                raise SourceDispositionNotVerbatim(
                    f"{self.row_id}: source_disposition {self.source_disposition!r} does not appear "
                    f"verbatim in canonical_source_text - the field may not be relabelled while "
                    f"quoting the real source row")
        else:
            # the source states no disposition for this row; only the terminal set may be assigned,
            # and the quote must still prove the obligation the row is being constructed for.
            if self.source_disposition not in TERMINAL_DISPOSITION_SET:
                raise UnresolvedSourceDisposition(
                    f"{self.row_id}: an ASSIGNED_TERMINAL_SET row may only use a token from the "
                    f"terminal disposition set {TERMINAL_DISPOSITION_SET}")

    # -- Axis B guards -------------------------------------------------------------------------
    def _assert_execution_axis(self) -> None:
        # an EMPTY execution_disposition is silent omission - report it as such, and do not let
        # the generic membership error mask the real defect.
        if not self.execution_disposition:
            raise LedgerDefect(f"{self.row_id}: silent omission - no execution disposition recorded")
        if self.execution_disposition not in EXEC_DISPOSITIONS:
            raise LedgerDefect(
                f"{self.row_id}: execution_disposition must be one of {EXEC_DISPOSITIONS}")
        if self.execution_disposition == "CONSUMED_ACTIVE":
            if not self.consumer:
                raise LedgerDefect(f"{self.row_id}: CONSUMED_ACTIVE requires a named consumer")
            if not self.readback_proof:
                raise LedgerDefect(f"{self.row_id}: CONSUMED_ACTIVE requires a readback proof, "
                                   f"not merely a recorded reference")
        if self.execution_disposition == "NOT_ACTIVE_WITH_REASON":
            if not self.not_active_reason:
                raise LedgerDefect(f"{self.row_id}: NOT_ACTIVE_WITH_REASON requires a reason")
            if not self.source_disposition:
                raise LedgerDefect(
                    f"{self.row_id}: a non-active row must still carry its canonical source "
                    f"disposition")

    def consume(self) -> dict:
        self._assert_source_axis()
        self._assert_execution_axis()
        # the two axes are orthogonal: neither implies nor rewrites the other.
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
        consumed = [r.consume() for r in rows]
        self.rows = consumed
        self.counts = {
            "total": len(consumed),
            "consumed_active": sum(1 for r in consumed if r["execution_disposition"] == "CONSUMED_ACTIVE"),
            "consumed_inactive": sum(1 for r in consumed if r["execution_disposition"] == "CONSUMED_INACTIVE"),
            "not_active_with_reason": sum(1 for r in consumed
                                          if r["execution_disposition"] == "NOT_ACTIVE_WITH_REASON"),
            "deferred": sum(1 for r in consumed if r["execution_disposition"] == "DEFERRED"),
            "unconsumed": sum(1 for r in consumed if not r["execution_disposition"]),
            # fidelity witness: how many distinct canonical source dispositions survived intact
            "distinct_source_dispositions": len({r["source_disposition"] for r in consumed}),
        }
        if self.counts["unconsumed"]:
            raise LedgerDefect(f"{self.counts['unconsumed']} row(s) have no execution disposition "
                               f"(silent omission is refused)")
        return self

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.counts, sort_keys=True).encode("utf-8")).hexdigest()
