import sys, os, subprocess, datetime, json
WT = "C:/Projects/Agent_Workspace/SWOF/.w2r9-worktree"
sys.path.insert(0, WT)
from types import SimpleNamespace
from src.security import policy_projection as pp

def req(op, **kw):
    d = dict(operation=op, effect_risk_tier="HIGH", permission_class="P3",
             required_authn_assurance="AAC2", required_authority="HA1",
             required_coapprovals=(), autonomy_tier="T2", independent_checker_required=False)
    d.update(kw)
    return SimpleNamespace(**d)

cases = [
    ("merge_HA1_only", req("remote_merge", effect_risk_tier="CRITICAL", permission_class="P5", required_authn_assurance="AAC3", autonomy_tier="T3", independent_checker_required=True)),
    ("merge_HA1_plus_HA3", req("remote_merge", effect_risk_tier="CRITICAL", permission_class="P5", required_authn_assurance="AAC3", autonomy_tier="T3", independent_checker_required=True, required_coapprovals=("HA3",))),
    ("stateful_MEDIUM", req("ACT-EXTERNAL-WRITE-STATEFUL", effect_risk_tier="MEDIUM")),
    ("identity_rights_no_domain", req("ACT-IDENTITY-RIGHTS", effect_risk_tier="HIGH")),
    ("delete_irrev_no_domain", req("ACT-DELETE-IRREV", effect_risk_tier="HIGH")),
    ("data_export_no_domain", req("ACT-DATA-EXPORT", effect_risk_tier="HIGH")),
    ("financial_no_domain", req("ACT-FINANCIAL", effect_risk_tier="HIGH")),
    ("physical_no_domain", req("ACT-PHYSICAL", effect_risk_tier="HIGH")),
    ("benign_read", req("read", effect_risk_tier="LOW", permission_class="P0", required_authn_assurance=None, autonomy_tier="T0")),
    ("release_positive", req("release", effect_risk_tier="CRITICAL", permission_class="P5", required_authn_assurance="AAC3", autonomy_tier="T3", independent_checker_required=True, required_coapprovals=("HA5",))),
    ("secret_positive", req("credential_access", effect_risk_tier="CRITICAL", permission_class="P4", required_authn_assurance="AAC3", autonomy_tier="T3", required_coapprovals=("HA3",))),
    ("reversible_write_positive", req("ACT-EXTERNAL-WRITE-REV", effect_risk_tier="MEDIUM", permission_class="P3")),
]

print("R9E_SOURCE_SHA=%s" % os.environ.get("R9E_SRC", "c333e47141393b4f6c39a13f70c96b31190f3c3d"))
print("CWD=%s" % WT)
print("PYTHON=%s" % sys.executable)
print("START=%s" % datetime.datetime.utcnow().isoformat() + "Z")
print("-" * 60)
result = {}
for name, r in cases:
    p = pp.minimum_policy(r.operation, effect_risk_tier=r.effect_risk_tier, permission_class=r.permission_class)
    errs = pp.policy_floor_errors(r)
    code = pp.policy_deny_code(errs)
    result[name] = {"action_class": p.action_class, "resolved": p.resolved,
                    "deferred": p.deferred_reason, "floor_errors": list(errs), "deny": code}
    print("%-26s action=%-28s resolved=%-5s deferred=%-22s floor=%s" % (
        name, p.action_class, p.resolved, p.deferred_reason, errs))
print("-" * 60)
print("END=%s" % datetime.datetime.utcnow().isoformat() + "Z")
print("EXIT_CODE=0")
open(os.environ["R9E_RESULT"], "w", newline="").write(json.dumps(result, indent=2) + "\n")
