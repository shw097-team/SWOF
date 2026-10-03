"""A security veto that proxies cannot bypass.

WHY: a pipeline that asks "is it green?" instead of "is there a security defect?" will ship a
secret leak behind a passing test suite, because success evidence and safety evidence are
different truth classes. Here ANY active veto signal vetoes (no threshold, no quorum), known
proxies are recorded and ignored, and anything ambiguous - an unknown signal, a non-boolean
value - fails closed as ACTIVE. The veto only blocks; it never approves anything.
"""
from __future__ import annotations

from dataclasses import dataclass

VETO_SIGNALS = frozenset({
    "untrusted_source_promoted", "secret_exposure", "permission_expansion",
    "human_gate_bypassed", "injection_quarantine_unresolved", "unpinned_dependency",
    "rights_violation",
})

PROXY_SIGNALS = frozenset({
    "provider_success", "test_green", "coverage_percent", "policy_file_present",
    "ci_green", "llm_judge_score",
})

OK = "OK"
VETO_ACTIVE = "VETO_ACTIVE"
VETO_ACTIVE_PROXIES_IGNORED = "VETO_ACTIVE_PROXIES_IGNORED"
UNKNOWN_SIGNAL_FAIL_CLOSED = "UNKNOWN_SIGNAL_FAIL_CLOSED"
AMBIGUOUS_SIGNAL_FAIL_CLOSED = "AMBIGUOUS_SIGNAL_FAIL_CLOSED"


class SecurityVetoActive(Exception):
    """The operation is vetoed and must not proceed."""

    code = "ERR_SECURITY_VETO_ACTIVE"


@dataclass(frozen=True)
class VetoDecision:
    """Veto outcome. A proxy can never set `vetoed` back to False."""

    vetoed: bool
    active_signals: tuple[str, ...]
    reason_code: str
    proxies_ignored: tuple[str, ...]
    proxy_cannot_override: bool = True


class SecurityVeto:
    """Evaluates veto signals. `strict=True` fails closed on anything it does not recognise."""

    def __init__(self, *, strict=True):
        self.strict = strict

    def _classify(self, signals, active, unknown, proxies_ignored):
        if isinstance(signals, dict):
            items = signals.items()
        elif isinstance(signals, (list, tuple, set, frozenset)):
            items = ((name, True) for name in signals)
        else:
            unknown.append("UNKNOWN_SIGNAL_CONTAINER_FAIL_CLOSED")
            return
        for name, value in items:
            if not isinstance(name, str) or not name:
                unknown.append("UNKNOWN_SIGNAL_NAME_FAIL_CLOSED")
                continue
            if name in PROXY_SIGNALS:
                proxies_ignored.append(name)
                continue
            if name not in VETO_SIGNALS:
                unknown.append(name)
                continue
            if value is False:
                continue
            if value is True:
                active.append(name)
            else:
                active.append(name)
                unknown.append("%s:AMBIGUOUS" % name)

    def evaluate(self, signals) -> VetoDecision:
        return self._decide(signals, None)

    def evaluate_with_proxies(self, signals, proxies) -> VetoDecision:
        return self._decide(signals, proxies)

    def _decide(self, signals, proxies) -> VetoDecision:
        active = []
        unknown = []
        proxies_ignored = []
        self._classify(signals, active, unknown, proxies_ignored)
        for name in _mapping_names(proxies):
            proxies_ignored.append(name)
        names = sorted(set(active))
        ambiguous = sorted({u for u in unknown if u.endswith(":AMBIGUOUS")})
        unknown_only = sorted({u for u in unknown if not u.endswith(":AMBIGUOUS")})
        proxy_names = tuple(sorted(set(proxies_ignored)))
        reason = OK
        if ambiguous:
            reason = AMBIGUOUS_SIGNAL_FAIL_CLOSED
        elif self.strict and unknown_only:
            reason = UNKNOWN_SIGNAL_FAIL_CLOSED
            names = sorted(set(names) | set(unknown_only))
        elif names:
            reason = VETO_ACTIVE_PROXIES_IGNORED if proxy_names else VETO_ACTIVE
        vetoed = bool(names)
        return VetoDecision(vetoed, tuple(names), reason, proxy_names)

    def assert_not_vetoed(self, decision) -> VetoDecision:
        """Raise `SecurityVetoActive` when vetoed; otherwise return the decision."""
        if not isinstance(decision, VetoDecision):
            raise SecurityVetoActive("UNKNOWN_DECISION_FAIL_CLOSED")
        if decision.vetoed:
            raise SecurityVetoActive(
                "vetoed (%s): %s" % (decision.reason_code, ", ".join(decision.active_signals)))
        return decision


def _mapping_names(proxies):
    if isinstance(proxies, dict):
        return [name for name in proxies if isinstance(name, str)]
    if isinstance(proxies, (list, tuple, set, frozenset)):
        return [name for name in proxies if isinstance(name, str)]
    return []
