"""unittest suite for multicast_guard.

Covers the six mandated acceptance scenarios plus schema/error-path,
determinism, receipt de-duplication, timing and migration rules.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from multicast_guard.errors import ValidationError  # noqa: E402
from multicast_guard.model import load_document, parse_case  # noqa: E402
from multicast_guard.planner import (  # noqa: E402
    pair_feasible, plan, scenario_survival,
)
from multicast_guard.topology import enumerate_trees  # noqa: E402
from multicast_guard.serialize import build_plan_payload  # noqa: E402
from multicast_guard.verifier import brute_force_crosscheck, verify  # noqa: E402

CASE_DIR = os.path.join(ROOT, "cases")


def case_path(name: str) -> str:
    return os.path.join(CASE_DIR, name)


def load(name: str):
    return parse_case(load_document(case_path(name)))


class SmallCaseFixtureTests(unittest.TestCase):
    """Every small case must cross-check against the independent oracle."""

    SMALL = [
        "case01_shared_domain.json",
        "case02_split_survival.json",
        "case03_cheap_reuse.json",
        "case04_forbidden_plain.json",
        "case05_revoked_generation.json",
        "case06_exact_deadline.json",
        "case08_infeasible.json",
    ]

    def test_brute_force_oracle_agrees(self):
        for name in self.SMALL:
            with self.subTest(name=name):
                case = load(name)
                cc = brute_force_crosscheck(case)
                self.assertTrue(cc["applied"], name)
                self.assertTrue(cc["tree_sets_agree"], name)
                self.assertTrue(cc["feasibility_agrees"], name)
                self.assertTrue(cc["optimum_cost_agrees"], name)
                self.assertFalse(
                    verify(case)["independent_rederivation"]["enumeration_capped"],
                    name,
                )


class Case01SharedDomainTests(unittest.TestCase):
    """Both trees reach every receiver alone, yet share a critical domain."""

    def setUp(self):
        self.case = load("case01_shared_domain.json")
        self.result = plan(self.case)

    def test_feasible_pair_exists(self):
        self.assertTrue(self.result.feasible)
        ta, tb = self.result.pair
        # Tree B's two receiver paths share the d3 ciphertext trunk.
        for tree in (ta, tb):
            for receiver in self.case.receivers:
                self.assertIn(receiver, tree.paths)

    def test_shared_critical_domain_on_one_tree(self):
        ta, tb = self.result.pair
        # Identify the tree whose every receiver path touches d3.
        d3_index = sorted(self.case.fault_domains).index("d3")
        shared = [
            t for t in (ta, tb)
            if all(p.domain_mask & (1 << d3_index) for p in t.paths.values())
        ]
        self.assertEqual(len(shared), 1)
        # When d3 fails, that tree loses both receivers but the other survives.
        dead_tree = shared[0]
        alive = scenario_survival(self.case, dead_tree, "d3")
        self.assertFalse(any(alive.values()))
        other = tb if dead_tree is ta else ta
        self.assertTrue(all(scenario_survival(self.case, other, "d3").values()))


class Case02SplitSurvivalTests(unittest.TestCase):
    """Both trees break under one fault, but each receiver keeps a branch."""

    def setUp(self):
        self.case = load("case02_split_survival.json")
        self.result = plan(self.case)

    def test_split_survival_per_receiver(self):
        self.assertTrue(self.result.feasible)
        ta, tb = self.result.pair
        # Domain d1 is crossed between receivers across the two trees.
        for failed in [None] + sorted(self.case.fault_domains):
            aa = scenario_survival(self.case, ta, failed)
            bb = scenario_survival(self.case, tb, failed)
            for receiver in self.case.receivers:
                self.assertTrue(aa[receiver] or bb[receiver],
                                (failed, receiver))

    def test_at_least_one_scenario_splits_receivers(self):
        ta, tb = self.result.pair
        split_found = False
        for did in self.case.fault_domains:
            aa = scenario_survival(self.case, ta, did)
            bb = scenario_survival(self.case, tb, did)
            if any(aa[r] and not bb[r] for r in aa) and any(
                bb[r] and not aa[r] for r in bb
            ):
                split_found = True
        self.assertTrue(split_found)


class Case03CheapReuseTests(unittest.TestCase):
    """Reusing the cheap funnel destroys resilience; baseline is rejected."""

    def setUp(self):
        self.case = load("case03_cheap_reuse.json")
        self.report = verify(self.case)

    def test_baseline_rejected_for_survival_not_permits(self):
        bv = self.report["baseline_verification"]
        self.assertFalse(bv["accepted"])
        first = bv["first_violation"]
        self.assertEqual(first["scope"], "baseline.pair")
        self.assertIn("loses both trees", first["reason"])

    def test_optimum_avoids_shared_funnel(self):
        result = plan(self.case)
        self.assertTrue(result.feasible)
        ta, tb = self.result_pair = result.pair
        a_edges = {e.id for e in ta.edges}
        b_edges = {e.id for e in tb.edges}
        # The resilient pair must not be the identical cheap d1 funnel.
        self.assertNotEqual(a_edges, b_edges)
        # Every receiver survives every single-domain fault.
        for did in self.case.fault_domains:
            self.assertIsNotNone(pair_feasible(self.case, ta, tb))


class Case04ForbiddenPlainTests(unittest.TestCase):
    """A relay outside the P permission set can never receive plaintext."""

    def setUp(self):
        self.case = load("case04_forbidden_plain.json")
        self.report = verify(self.case)

    def test_baseline_flags_forbidden_relay_first(self):
        first = self.report["baseline_verification"]["first_violation"]
        self.assertEqual(first["node"], "A")
        self.assertIn("plaintext", first["reason"])

    def test_no_candidate_tree_exposes_plaintext_to_A(self):
        trees, _ = enumerate_trees(self.case)
        for tree in trees:
            for path in tree.paths.values():
                for idx, node in enumerate(path.node_path):
                    if node == "A":
                        # A's inbound label (previous edge) must be ciphertext.
                        self.assertNotEqual("P", path.label_path[idx - 1])

    def test_resilient_pair_is_feasible_via_ciphertext(self):
        self.assertTrue(plan(self.case).feasible)


class Case05RevokedGenerationTests(unittest.TestCase):
    """Old generation after P withdrawal: explicit drop, no early confirm."""

    def setUp(self):
        self.case = load("case05_revoked_generation.json")
        self.payload = build_plan_payload(self.case)
        self.audit = self.payload["migration_audit"]

    def test_old_plaintext_copy_dropped_before_relay(self):
        drops = self.audit["drops"]
        self.assertTrue(drops)
        drop = drops[0]
        self.assertEqual(drop["forbidden_node"], "A")
        # The cut happens on the edge entering A, at its predecessor.
        self.assertEqual(drop["drop_at_node"], "P0")
        self.assertEqual(drop["drop_at_edge"], "e01")
        self.assertEqual(drop["event_order"], "policy_first_then_arrival")

    def test_new_receiver_not_used_for_old_confirmation(self):
        self.assertIn("R3",
                      self.audit["new_receivers_ignored_for_old_messages"])
        old_dir = set(self.audit["old_receiver_directory"])
        for receipt in self.audit["receipts"]:
            self.assertIn(receipt["receiver"], old_dir)

    def test_one_receipt_per_digest_receiver(self):
        keys = [(r["digest"], r["receiver"]) for r in self.audit["receipts"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_late_branch_checked_inside_overlap(self):
        self.assertIsNotNone(self.audit["window_overlap"])
        for tree in self.audit["trees"]:
            for entry in tree["path_audit"]:
                self.assertIsNotNone(entry["late_branch_arrival_window"])


class Case06ExactDeadlineTests(unittest.TestCase):
    """An arrival exactly at the deadline is accepted."""

    def setUp(self):
        self.case = load("case06_exact_deadline.json")
        self.report = verify(self.case)

    def test_exact_deadline_arrival_on_time(self):
        rs = self.report["requested_scenario"]
        self.assertEqual(rs["publish_time"], 10)
        self.assertTrue(rs["deadline_inclusive"])
        for row in rs["per_receiver"]:
            self.assertTrue(row["arrives_by_deadline"])
            # Latest arrival equals the deadline exactly.
            windows = [row["tree_a_arrival_window"],
                       row["tree_b_arrival_window"]]
            self.assertIn(20, [w[1] for w in windows if w])

    def test_grid_marks_deadline_inclusive(self):
        grid = self.report["timing_grid"]
        self.assertTrue(grid["computed"])
        last_time_rows = [r for r in grid["rows"]
                          if r["publish_time"] == 10]
        self.assertTrue(all(
            r["tree_a_on_time"] or r["tree_b_on_time"]
            for r in last_time_rows
        ))


class FullScaleCaseTests(unittest.TestCase):
    """18 nodes / 32 edges / 7 receivers / 6 fault domains."""

    def setUp(self):
        self.case = load("case07_full_scale.json")

    def test_published_dimensions(self):
        self.assertEqual(len(self.case.nodes), 18)
        self.assertEqual(len(self.case.edges), 32)
        self.assertEqual(len(self.case.receivers), 7)
        self.assertEqual(len(self.case.fault_domains), 6)

    def test_feasible_and_bounded_search_reported(self):
        result = plan(self.case)
        self.assertTrue(result.feasible)
        self.assertTrue(result.capped)  # bounded beam, honestly reported
        ta, tb = result.pair
        self.assertIsNotNone(pair_feasible(self.case, ta, tb))

    def test_every_receiver_survives_every_domain(self):
        ta, tb = plan(self.case).pair
        for failed in [None] + sorted(self.case.fault_domains):
            aa = scenario_survival(self.case, ta, failed)
            bb = scenario_survival(self.case, tb, failed)
            for receiver in self.case.receivers:
                self.assertTrue(aa[receiver] or bb[receiver],
                                (failed, receiver))

    def test_cost_tuple_ordering(self):
        result = plan(self.case)
        ta, tb = result.pair
        fee, transforms, worst = result.cost
        distinct = {e.id for e in ta.edges} | {e.id for e in tb.edges}
        self.assertEqual(fee, sum(self.case.edges[e].cost for e in distinct))
        self.assertEqual(transforms, ta.transform_count + tb.transform_count)
        self.assertEqual(worst, max(ta.worst_max_arrival,
                                    tb.worst_max_arrival))


class InfeasibleCaseTests(unittest.TestCase):
    """No dual tree exists: a replayable witness must be provided."""

    def setUp(self):
        self.case = load("case08_infeasible.json")
        self.report = verify(self.case)

    def test_infeasibility_rederived_and_cross_checked(self):
        redev = self.report["independent_rederivation"]
        self.assertFalse(redev["feasible"])
        self.assertEqual(redev["witness"]["kind"], "no_feasible_pair")
        cc = self.report["small_graph_crosscheck"]
        self.assertTrue(cc["feasibility_agrees"])
        self.assertFalse(cc["brute_force_feasible"])

    def test_baseline_rejected_with_replay_witness(self):
        bv = self.report["baseline_verification"]
        self.assertFalse(bv["accepted"])
        witness = bv["replay_witness"]
        self.assertEqual(witness["kind"], "survival_failure")
        self.assertEqual(witness["receiver"], "R1")
        self.assertEqual(witness["scenario"], "d1")
        self.assertIn("replay", witness)
        # Both recorded paths are concrete and re-walkable.
        self.assertEqual(witness["tree_a_path"]["node_path"][0], "P0")
        self.assertEqual(witness["tree_b_path"]["node_path"][-1], "R1")


class SchemaValidationTests(unittest.TestCase):
    def test_malformed_document_reports_field_path(self):
        doc = {
            "schema_version": "x", "case_id": "bad", "version": "v",
            "nodes": [{"id": "P0", "role": "publisher"}],
            "edges": [{"id": "e1", "src": "P0", "dst": "P0",
                       "allowed_labels": ["X"], "max_classification": -1,
                       "delay_min": 5, "delay_max": 1,
                       "fault_domain": "nope", "cost": -2}],
            "topics": [], "message": {"id": "m"},
        }
        with self.assertRaises(ValidationError) as ctx:
            parse_case(doc)
        paths = {e["path"] for e in ctx.exception.errors}
        self.assertIn("edges[0].dst", paths)
        self.assertIn("edges[0].allowed_labels", paths)
        self.assertIn("edges[0].delay_min", paths)
        self.assertIn("edges[0].fault_domain", paths)

    def test_permit_version_mixing_rejected(self):
        doc = load_document(case_path("case01_shared_domain.json"))
        doc["permits"][0]["version"] = "other-version"
        with self.assertRaises(ValidationError) as ctx:
            parse_case(doc)
        self.assertTrue(
            any("version" in e["message"] for e in ctx.exception.errors))


class DeterminismTests(unittest.TestCase):
    def test_plan_output_byte_stable(self):
        case = load("case02_split_survival.json")
        first = json.dumps(build_plan_payload(case), ensure_ascii=False,
                           sort_keys=True)
        second = json.dumps(build_plan_payload(case), ensure_ascii=False,
                            sort_keys=True)
        self.assertEqual(first, second)

    def test_cli_emits_utf8_json(self):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, "-m", "multicast_guard", "plan",
             case_path("case02_split_survival.json")],
            cwd=ROOT, capture_output=True, env=env, check=True,
        )
        text = proc.stdout.decode("utf-8")
        d = json.loads(text)
        self.assertEqual(d["command"], "plan")
        self.assertTrue(d["feasible"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
