"""Deterministic JSON serialization of planner and verifier results."""

from __future__ import annotations

from .audit import audit_previous
from .model import Case
from .planner import NO_FAULT, plan, scenario_survival
from .topology import BuiltTree, arrival_window


def _tree_payload(tree: BuiltTree, case: Case, order: str) -> dict:
    msg = case.message
    paths = {}
    for receiver in case.receivers:
        path = tree.paths[receiver]
        earliest, latest = arrival_window(path, msg.window_earliest)
        worst_earliest, worst_latest = arrival_window(path, msg.window_latest)
        paths[receiver] = {
            "node_path": list(path.node_path),
            "edge_path": list(path.edge_path),
            "label_path": list(path.label_path),
            "transit_nodes": sorted(path.transit_nodes),
            "delay_interval": [path.delay_min, path.delay_max],
            "arrival_window_earliest_publish": [earliest, latest],
            "arrival_window_latest_publish": [worst_earliest, worst_latest],
            "worst_case_arrival": worst_latest,
            "on_time_at_deadline": worst_latest <= msg.deadline,
            "domain_mask": path.domain_mask,
        }
    return {
        "tree_id": tree.tree_id,
        "ordering_role": order,
        "root": tree.root,
        "edges": [
            {"edge_id": eid, "label": tree.edge_labels[eid]}
            for eid, _lab in tree.canonical_edge_seq
        ],
        "canonical_edge_sequence": [list(x) for x in tree.canonical_edge_seq],
        "transforms": [
            {"node": n, "from_label": f, "to_label": t, "permit_id": pid}
            for n, f, t, pid in tree.canonical_transform_seq
        ],
        "canonical_transform_sequence": [list(x) for x in tree.canonical_transform_seq],
        "used_permit_ids": sorted(tree.used_permits),
        "edge_cost": tree.edge_cost,
        "transform_count": tree.transform_count,
        "worst_max_arrival": tree.worst_max_arrival,
        "paths": {r: paths[r] for r in sorted(paths)},
    }


def _survival_payload(case: Case, trees: list[BuiltTree]) -> dict:
    scenarios = [NO_FAULT] + sorted(case.fault_domains)
    per_scenario = {}
    for failed in scenarios:
        name = failed
        rows = {}
        for idx, tree in enumerate(trees):
            alive = scenario_survival(case, tree, None if failed == NO_FAULT else failed)
            for receiver, ok in alive.items():
                rows.setdefault(receiver, {})[f"tree_{'ab'[idx]}_alive"] = ok
        for receiver in rows:
            a = rows[receiver]["tree_a_alive"]
            b = rows[receiver]["tree_b_alive"]
            rows[receiver]["delivered_by"] = (
                "tree_a" if a and not b
                else "tree_b" if b and not a
                else "both" if a and b
                else "neither"
            )
        per_scenario[name] = rows
    return {
        "scenarios": scenarios,
        "rule": "each receiver needs at least one surviving path per scenario; "
                "trees are never compared as whole domain sets",
        "per_scenario": per_scenario,
    }


def build_plan_payload(case: Case) -> dict:
    result = plan(case)
    payload: dict = {
        "command": "plan",
        "schema_version": case.schema_version,
        "case_id": case.case_id,
        "version": case.version,
        "message": {
            "id": case.message.id,
            "topic": case.message.topic,
            "digest": case.message.digest,
            "generation": case.message.generation,
            "publisher": case.message.publisher,
            "publish_window": [case.message.window_earliest, case.message.window_latest],
            "deadline": case.message.deadline,
        },
        "event_order_rule": "policy_first_then_arrival; deadline arrivals are inclusive",
        "feasible": result.feasible,
        "stats": result.stats,
    }
    if result.feasible:
        tree_a, tree_b = result.trees
        payload["trees"] = [
            _tree_payload(tree_a, case, "first"),
            _tree_payload(tree_b, case, "second"),
        ]
        payload["cost"] = {
            "distinct_edge_fee": result.cost[0],
            "total_transforms": result.cost[1],
            "worst_delivery_time": result.cost[2],
            "tuple": list(result.cost),
        }
        payload["permit_sets_disjoint"] = not (
            tree_a.used_permits & tree_b.used_permits
        )
        payload["fault_survival"] = _survival_payload(case, result.trees)
        payload["receipts"] = _receipts(case, result.trees)
    else:
        payload["witness"] = result.witness
    payload["migration_audit"] = audit_previous(case)
    return payload


def _receipts(case: Case, trees: list[BuiltTree]) -> dict:
    # Same version + same digest arriving over either tree yields exactly one
    # receipt per receiver.
    receipts = []
    for receiver in case.receivers:
        delivering_trees = []
        for idx, tree in enumerate(trees):
            if receiver in tree.paths:
                delivering_trees.append(f"tree_{'ab'[idx]}")
        receipts.append({
            "digest": case.message.digest,
            "generation": case.message.generation,
            "receiver": receiver,
            "delivering_trees": delivering_trees,
            "receipt_count": 1,
            "dedup_rule": "one receipt per (digest, receiver) regardless of tree count",
        })
    return {
        "receipts": sorted(receipts, key=lambda r: r["receiver"]),
        "dedup_key": ["digest", "receiver"],
    }
