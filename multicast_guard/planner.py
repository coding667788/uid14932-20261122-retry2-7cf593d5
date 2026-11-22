"""Dual-tree planner: enumeration, pair selection and replayable witnesses."""

from __future__ import annotations

from dataclasses import dataclass

from .model import Case
from .topology import BuiltTree, PathInfo, enumerate_trees, tree_sort_key

NO_FAULT = "no_fault"


@dataclass
class PlanResult:
    feasible: bool
    trees: list[BuiltTree]
    pair: tuple[BuiltTree, BuiltTree] | None
    cost: tuple | None
    capped: bool
    witness: dict
    stats: dict


def scenario_survival(
    case: Case, tree: BuiltTree, failed_domain: str | None
) -> dict[str, bool]:
    """Per-receiver liveness for one fault scenario.

    A receiver's path survives iff it touches neither a failed edge nor a
    failed transit node of the given domain.  Liveness is judged per receiver;
    the two trees are never compared as whole domain sets.
    """
    alive: dict[str, bool] = {}
    for receiver, path in tree.paths.items():
        if failed_domain is None:
            alive[receiver] = True
            continue
        mask = case.fault_domains[failed_domain]
        edge_dead = any(eid in mask.edges for eid in path.edge_path)
        node_dead = any(nid in mask.nodes for nid in path.transit_nodes)
        alive[receiver] = not edge_dead and not node_dead
    return alive


def pair_feasible(case: Case, tree_a: BuiltTree, tree_b: BuiltTree) -> dict | None:
    """Return a per-receiver, per-scenario liveness table or ``None``."""
    if tree_a.used_permits & tree_b.used_permits:
        return None
    scenarios = [None] + sorted(case.fault_domains)
    table: dict[str, dict[str, str]] = {}
    for failed in scenarios:
        alive_a = scenario_survival(case, tree_a, failed)
        alive_b = scenario_survival(case, tree_b, failed)
        scenario_name = NO_FAULT if failed is None else failed
        for receiver in case.receivers:
            a_ok = alive_a.get(receiver, False)
            b_ok = alive_b.get(receiver, False)
            if not (a_ok or b_ok):
                return None
            table.setdefault(receiver, {})[scenario_name] = (
                "tree_a" if a_ok and not b_ok
                else "tree_b" if b_ok and not a_ok
                else "both"
            )
    return table


def pair_cost(tree_a: BuiltTree, tree_b: BuiltTree, case: Case) -> tuple:
    distinct_edges = {e.id for e in tree_a.edges} | {e.id for e in tree_b.edges}
    # An edge reused by both trees is paid exactly once.
    edge_fee = sum(case.edges[eid].cost for eid in distinct_edges)
    return (
        edge_fee,
        tree_a.transform_count + tree_b.transform_count,
        max(tree_a.worst_max_arrival, tree_b.worst_max_arrival),
    )


def canonical_tiebreak(tree_a: BuiltTree, tree_b: BuiltTree) -> tuple:
    return (
        tree_a.canonical_edge_seq,
        tree_a.canonical_transform_seq,
        tree_b.canonical_edge_seq,
        tree_b.canonical_transform_seq,
    )


def plan(case: Case) -> PlanResult:
    candidates, capped = enumerate_trees(case)
    stats = {
        "candidate_trees": len(candidates),
        "enumeration_capped": capped,
        "pairs_evaluated": 0,
        "pairs_permit_conflict": 0,
        "pairs_survival_failed": 0,
    }
    if not candidates:
        return PlanResult(
            feasible=False, trees=[], pair=None, cost=None, capped=capped,
            witness=_empty_enumeration_witness(case), stats=stats,
        )

    best: tuple | None = None
    best_pair: tuple[BuiltTree, BuiltTree] | None = None
    best_table: dict | None = None
    best_obstruction: dict | None = None
    n = len(candidates)
    for i in range(n):
        for j in range(i + 1, n):
            stats["pairs_evaluated"] += 1
            ta, tb = candidates[i], candidates[j]
            if ta.used_permits & tb.used_permits:
                stats["pairs_permit_conflict"] += 1
                obstruction = {"reason": "shared_permit",
                               "permit_ids": sorted(ta.used_permits & tb.used_permits)}
            else:
                table = pair_feasible(case, ta, tb)
                if table is None:
                    stats["pairs_survival_failed"] += 1
                    obstruction = _survival_obstruction(case, ta, tb)
                else:
                    cost = pair_cost(ta, tb, case)
                    # Smaller tree first when no primary/standby ordering is given.
                    ordered = sorted((ta, tb), key=tree_sort_key)
                    tie = canonical_tiebreak(ordered[0], ordered[1])
                    key = cost + tie
                    if best is None or key < best:
                        best = key
                        best_pair = (ordered[0], ordered[1])
                        best_table = table
                    continue
            if best_obstruction is None:
                best_obstruction = obstruction
                best_obstruction["tree_a"] = ta.tree_id
                best_obstruction["tree_b"] = tb.tree_id

    if best_pair is None:
        witness = {
            "kind": "no_feasible_pair",
            "candidate_trees": n,
            "first_blocking_pair": best_obstruction,
            "receiver_domain_coverage": _coverage_witness(case, candidates),
        }
        return PlanResult(False, candidates, None, None, capped, witness, stats)

    return PlanResult(
        feasible=True,
        trees=list(best_pair),
        pair=best_pair,
        cost=best[:3],
        capped=capped,
        witness={"kind": "feasible", "survival_table": best_table},
        stats=stats,
    )


def _survival_obstruction(case: Case, ta: BuiltTree, tb: BuiltTree) -> dict:
    scenarios = [None] + sorted(case.fault_domains)
    for failed in scenarios:
        alive_a = scenario_survival(case, ta, failed)
        alive_b = scenario_survival(case, tb, failed)
        for receiver in case.receivers:
            if not (alive_a.get(receiver, False) or alive_b.get(receiver, False)):
                return {
                    "reason": "receiver_lost",
                    "scenario": NO_FAULT if failed is None else failed,
                    "receiver": receiver,
                    "tree_a_path": _path_summary(ta.paths.get(receiver)),
                    "tree_b_path": _path_summary(tb.paths.get(receiver)),
                }
    return {"reason": "unknown"}


def _path_summary(path: PathInfo | None) -> dict | None:
    if path is None:
        return None
    return {
        "node_path": list(path.node_path),
        "edge_path": list(path.edge_path),
        "label_path": list(path.label_path),
        "delay_min": path.delay_min,
        "delay_max": path.delay_max,
        "domain_mask": path.domain_mask,
    }


def _coverage_witness(case: Case, candidates: list[BuiltTree]) -> list[dict]:
    """For every receiver, the union of domain masks its candidate paths touch."""
    coverage = []
    for receiver in case.receivers:
        union = 0
        available = 0
        for tree in candidates:
            path = tree.paths.get(receiver)
            if path is not None:
                available += 1
                union |= path.domain_mask
        domain_names = [
            did for i, did in enumerate(sorted(case.fault_domains))
            if union & (1 << i)
        ]
        coverage.append({
            "receiver": receiver,
            "candidate_paths": available,
            "domains_touched_by_candidate_paths": domain_names,
        })
    return coverage


def _empty_enumeration_witness(case: Case) -> dict:
    msg = case.message
    topic = case.topics[msg.topic]
    reasons = []
    if msg.publisher not in topic.plain_allowed:
        reasons.append({
            "reason": "publisher_without_plain_permission",
            "node": msg.publisher,
        })
    for receiver in case.receivers:
        reachable = _any_reachable_edge_path(case, receiver)
        if not reachable:
            reasons.append({
                "reason": "receiver_topologically_unreachable",
                "receiver": receiver,
            })
    return {
        "kind": "no_candidate_tree",
        "candidate_trees": 0,
        "blocking_facts": reasons,
        "survival_scenarios": [NO_FAULT] + sorted(case.fault_domains),
        "publish_window": [msg.window_earliest, msg.window_latest],
        "deadline": msg.deadline,
    }


def _any_reachable_edge_path(case: Case, target: str) -> bool:
    seen = {case.message.publisher}
    queue = [case.message.publisher]
    while queue:
        u = queue.pop(0)
        for edge in case.out_edges.get(u, []):
            if edge.dst not in seen:
                seen.add(edge.dst)
                queue.append(edge.dst)
    return target in seen
