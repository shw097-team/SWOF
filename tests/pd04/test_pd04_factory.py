"""W0-003 exit tests - the PD04 packet factory must be able to FAIL (RBWI 10.4)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from pd04.factory import (  # noqa: E402
    ECP, PD04RouteError, TaskSpec, TaskSpecSeed, compile_packet,
)


def good():
    seed = TaskSpecSeed(
        workorder_id="WO-X", wave="W1", objective="obj",
        source_requirement_locators=[{"package": "PI-PKG-04"}],
        fresh_repocontext_ref="var/pd03_repocontext.json", wave_basis="RBWI 10.2")
    ts = TaskSpec(taskspec_id="TS-WO-X", workorder_id="WO-X", objective="obj",
                  proposed_bounded_write_set=["SWOF/src/fabric/*"],
                  acceptance_edges=["acc"], evidence_edges=["ev"], security_edges=["sec"],
                  rollback_edges=["rb"], invalidation_edges=["inv"])
    return seed, ts


class TestPD04Factory(unittest.TestCase):
    def test_compiles_one_ecp_per_workorder(self):
        seed, ts = good()
        p = compile_packet(seed, ts)
        d = p.to_dict()
        self.assertEqual(d["schema"], "PD04-CONSTRUCTION-PACKET/1")
        self.assertEqual(len([d["ecp"]]), 1)
        self.assertEqual(d["ecp"]["ecp_id"], "ECP-WO-X")
        self.assertEqual(d["workorder"]["state"], "PLANNED_NOT_DISPATCHED")
        self.assertIsNone(d["execution_binding"])

    def test_control_case_routable(self):
        seed, ts = good()
        compile_packet(seed, ts).assert_routable()  # must NOT raise

    def test_missing_fresh_repocontext_fails_closed(self):
        seed, ts = good()
        seed.fresh_repocontext_ref = None
        with self.assertRaises(PD04RouteError) as ctx:
            compile_packet(seed, ts)
        self.assertEqual(ctx.exception.code, "FAIL_PD04_ROUTE")
        self.assertIn("fresh_repocontext_ref", ctx.exception.missing)

    def test_missing_acceptance_edges_fails_closed(self):
        seed, ts = good()
        ts.acceptance_edges = []
        with self.assertRaises(PD04RouteError):
            compile_packet(seed, ts)

    def test_missing_evidence_edges_fails_closed(self):
        seed, ts = good()
        ts.evidence_edges = []
        with self.assertRaises(PD04RouteError):
            compile_packet(seed, ts)

    def test_missing_source_requirement_edges_fails_closed(self):
        seed, ts = good()
        seed.source_requirement_locators = []
        with self.assertRaises(PD04RouteError):
            compile_packet(seed, ts)

    def test_packet_fingerprint_is_deterministic(self):
        seed, ts = good()
        self.assertEqual(compile_packet(seed, ts).fingerprint(),
                         compile_packet(seed, ts).fingerprint())

    def test_schema_requires_all_route_refs(self):
        schema = json.loads((ROOT / "schemas" / "pd04" / "construction_packet.schema.json")
                            .read_text(encoding="utf-8"))
        for k in ("fresh_repocontext_ref", "pd04_packet_ref", "taskspec_ref", "ecp_ref",
                  "source_requirement_edges", "acceptance_edges", "evidence_edges"):
            self.assertIn(k, schema["required"], f"schema must require {k}")


if __name__ == "__main__":
    unittest.main()
