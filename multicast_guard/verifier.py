"""Independent re-computation and verification (the ``check`` command).

The verifier never trusts planner output: it rebuilds every tree from its
edge/transform list, re-derives paths, timing and fault survival, and reports
the first rule-breaking transit point or the first lost receiver together
with the full path.  On small graphs it additionally brute-forces *every*
edge-subset arborescence to cross-check feasibility and cost.
"""

from __future__ import annotations

import itertools

from .model import Case, Permit, TransformSpec, TreeSpec
from .planner import (
    NO_FAULT,
    pair_cost,
    pair_feasible,
    plan,
    scenario_survival,
)
from .topology import (
    BuiltTree,
    LABEL_PLAIN,
    PathInfo,
    Violation,
    build_tree_from_spec,
    enumerate_trees,
    tree_sort_key,
)


def verify(case: Case) -> dict:
    # 1. Independently re-derive what is feasible on this input.
    result = plan(case)
    payload: dict = {
        "case_id": case.case_id,
        "version": case.version,
        "independent_rederivation": {
            "feasible": result.feasible,
            "candidate_trees": result.stats["candidate_trees"],
            "pairs_evaluated": result.stats["pairs_evaluated"],
            "enumeration_capped": result.capped,
            "witness": result.witness,
        },
    }

    # 2. Small-graph subset brute force cross-check.
    payload["small_graph_crosscheck"] = brute_force_crosscheck(case)

    # 3. Verify the explicitly supplied baseline when present.
    if case.baseline is not None:
        payload["baseline_verification"] = _verify_baseline(case)
    else:
        payload["baseline_verification"] = {"present": False}

    # 4. Reproducible scenario/timing walk for the requested publish instant.
    payload["requested_scenario"] = _requested_scenario(case, result)

    # 5. Full timing grid: every allowed publish time, arrival windows summed
    # from the integer closed edge delay intervals.
    payload["timing_grid"] = _timing_grid(case, result)
    return payload


# --------------------------------------------------------------------------- #
# Baseline verification
# --------------------------------------------------------------------------- #

def _verify_baseline(case: Case) -> dict:
    permits_by_id = {p.id: p for p in case.permits}
    spec_a, spec_b = case.baseline
    # Baseline trees name their own permits: validate those exact bindings
    # instead of re-allocating the smallest-id permit.
    tree_a, viol_a = build_tree_from_spec(
        case, spec_a, permits_by_id, "baseline.tree_a",
        trust_declared_permits=True)
    tree_b, viol_b = build_tree_from_spec(
        case, spec_b, permits_by_id, "baseline.tree_b",
        trust_declared_permits=True)

    response: dict = {"present": True}
    all_violations = [("baseline.tree_a", v) for v in viol_a] + [
        ("baseline.tree_b", v) for v in viol_b
    ]
    if all_violations:
        first_scope, first = sorted(all_violations, key=lambda sv: sv[1].order)[0]
        response["accepted"] = False
        response["first_violation"] = {"scope": first_scope, **first.to_dict()}
        response["all_violations"] = [
            {"scope": scope, **v.to_dict()} for scope, v in all_violations
        ]
        response["replay_witness"] = _baseline_failure_witness(case, first)
        return response

    # Both trees build: check the joint failure semantics independently.
    table = pair_feasible(case, tree_a, tree_b)
    if table is None:
        lost = _first_lost_receiver(case, tree_a, tree_b)
        response["accepted"] = False
        response["first_violation"] = {
            "scope": "baseline.pair",
            "point": "joint fault semantics",
            "reason": "a receiver loses both trees under one fault scenario",
            **lost,
        }
        response["replay_witness"] = {
            "kind": "survival_failure",
            "replay": {
                "command": "python -m multicast_guard check CASE.json",
                "case_id": case.case_id,
                "version": case.version,
            },
            **lost,
            "survival_scenarios": [NO_FAULT] + sorted(case.fault_domains),
        }
        return response

    timing_issue = _first_deadline_failure(case, tree_a, tree_b)
    if timing_issue is not None:
        response["accepted"] = False
        response["first_violation"] = {"scope": "baseline.pair", **timing_issue}
        response["replay_witness"] = {"kind": "deadline_failure", **timing_issue}
        return response

    response["accepted"] = True
    response["survival_table"] = table
    response["cost"] = list(pair_cost(tree_a, tree_b, case))
    response["permit_sets_disjoint"] = not (
        tree_a.used_permits & tree_b.used_permits
    )
    return response


def _first_lost_receiver(case: Case, tree_a: BuiltTree, tree_b: BuiltTree) -> dict:
    scenarios = [None] + sorted(case.fault_domains)
    for failed in scenarios:
        alive_a = scenario_survival(case, tree_a, failed)
        alive_b = scenario_survival(case, tree_b, failed)
        for receiver in case.receivers:
            if not (alive_a.get(receiver, False) or alive_b.get(receiver, False)):
                return {
                    "scenario": NO_FAULT if failed is None else failed,
                    "receiver": receiver,
                    "tree_a_path": _summarise(tree_a.paths.get(receiver)),
                    "tree_b_path": _summarise(tree_b.paths.get(receiver)),
                }
    return {}


def _first_deadline_failure(case: Case, tree_a: BuiltTree, tree_b: BuiltTree) -> dict | None:
    msg = case.message
    for tree in (tree_a, tree_b):
        for receiver in sorted(tree.paths):
            path = tree.paths[receiver]
            worst_arrival = msg.window_latest + path.delay_max
            if worst_arrival > msg.deadline:
                return {
                    "point": f"{tree.tree_id}.path:{receiver}",
                    "reason": "worst-case arrival misses the deadline",
                    "receiver": receiver,
                    "worst_case_arrival": worst_arrival,
                    "deadline": msg.deadline,
                    "path": _summarise(path),
                }
    return None


def _baseline_failure_witness(case: Case, first: Violation) -> dict:
    return {
        "kind": "structural_failure",
        "first_violation": first.to_dict(),
        "replay": {
            "command": "python -m multicast_guard check CASE.json",
            "case_id": case.case_id,
            "version": case.version,
        },
        "survival_scenarios": [NO_FAULT] + sorted(case.fault_domains),
    }


def _summarise(path: PathInfo | None) -> dict | None:
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


# --------------------------------------------------------------------------- #
# Requested scenario replay and timing grid
# --------------------------------------------------------------------------- #

def _requested_scenario(case: Case, result) -> dict:
    if case.check_publish_time is None:
        return {"present": False}
    publish_time = case.check_publish_time
    failed = case.check_failed_domain
    out: dict = {
        "present": True,
        "publish_time": publish_time,
        "failed_domain": failed,
        "event_order": "policy_first_then_arrival",
        "deadline_inclusive": True,
    }
    if not result.feasible:
        out["note"] = "no feasible dual tree exists; reporting baseline/obstruction instead"
        return out
    tree_a, tree_b = result.pair
    alive_a = scenario_survival(case, tree_a, failed)
    alive_b = scenario_survival(case, tree_b, failed)
    rows = []
    for receiver in case.receivers:
        rows.append({
            "receiver": receiver,
            "tree_a_alive": alive_a[receiver],
            "tree_b_alive": alive_b[receiver],
            "delivered_by": (
                "tree_a" if alive_a[receiver] and not alive_b[receiver]
                else "tree_b" if alive_b[receiver] and not alive_a[receiver]
                else "both" if alive_a[receiver] and alive_b[receiver]
                else "neither"
            ),
            "tree_a_arrival_window": _arrival(tree_a, receiver, publish_time),
            "tree_b_arrival_window": _arrival(tree_b, receiver, publish_time),
            "arrives_by_deadline": _any_on_time(
                case, tree_a, tree_b, receiver, publish_time,
                alive_a[receiver], alive_b[receiver]
            ),
        })
    out["per_receiver"] = rows
    out["first_lost_receiver"] = next(
        (r["receiver"] for r in rows if r["delivered_by"] == "neither"), None
    )
    return out


def _arrival(tree: BuiltTree, receiver: str, publish_time: int):
    path = tree.paths.get(receiver)
    if path is None:
        return None
    return [publish_time + path.delay_min, publish_time + path.delay_max]


def _any_on_time(case, tree_a, tree_b, receiver, publish_time, a_alive, b_alive):
    deadline = case.message.deadline
    ok = False
    if a_alive:
        w = _arrival(tree_a, receiver, publish_time)
        ok = ok or (w is not None and w[0] <= deadline)
    if b_alive:
        w = _arrival(tree_b, receiver, publish_time)
        ok = ok or (w is not None and w[0] <= deadline)
    return ok


def _timing_grid(case: Case, result) -> dict:
    """Per publish-time/per-receiver arrival windows across both chosen trees."""
    if not result.feasible:
        return {"computed": False, "reason": "no feasible dual tree"}
    tree_a, tree_b = result.pair
    msg = case.message
    rows = []
    for publish_time in range(msg.window_earliest, msg.window_latest + 1):
        for receiver in case.receivers:
            wa = _arrival(tree_a, receiver, publish_time)
            wb = _arrival(tree_b, receiver, publish_time)
            rows.append({
                "publish_time": publish_time,
                "receiver": receiver,
                "tree_a_arrival_window": wa,
                "tree_b_arrival_window": wb,
                "tree_a_on_time": wa is not None and wa[0] <= msg.deadline,
                "tree_b_on_time": wb is not None and wb[0] <= msg.deadline,
                "deadline": msg.deadline,
            })
    return {
        "computed": True,
        "delay_semantics": "integer closed delay intervals; arrival windows are summed",
        "rows": rows,
    }


# --------------------------------------------------------------------------- #
# Independent small-graph brute force
# --------------------------------------------------------------------------- #

SMALL_GRAPH_EDGE_LIMIT = 10
SMALL_GRAPH_NODE_LIMIT = 9


def brute_force_crosscheck(case: Case) -> dict:
    """Enumerate every edge subset on small graphs as an independent oracle.

    Unlike :func:`multicast_guard.topology.enumerate_trees` (a DFS closure
    enumeration), this routine iterates over powerset edge subsets and keeps
    exactly those forming a valid receiver-covering rooted arborescence.
    """
    node_count = len(case.nodes)
    edge_count = len(case.edges)
    if node_count > SMALL_GRAPH_NODE_LIMIT or edge_count > SMALL_GRAPH_EDGE_LIMIT:
        return {
            "applied": False,
            "reason": f"cross-check only runs on <= {SMALL_GRAPH_NODE_LIMIT} nodes "
                      f"and <= {SMALL_GRAPH_EDGE_LIMIT} edges",
            "node_count": node_count,
            "edge_count": edge_count,
        }

    edge_list = sorted(case.edges.values(), key=lambda e: e.id)
    topic = case.topics[case.message.topic]
    root = case.message.publisher
    receiver_set = set(case.receivers)
    permits_by_id = {p.id: p for p in case.permits}
    valid: list[BuiltTree] = []
    subsets_scanned = 0

    for r in range(1, len(edge_list) + 1):
        for idxs in itertools.combinations(range(len(edge_list)), r):
            label_options = [
                sorted(edge_list[i].allowed_labels) for i in idxs
            ]
            for label_combo in itertools.product(*label_options):
                subsets_scanned += 1
                labelled = tuple(
                    (edge_list[i], label_combo[k]) for k, i in enumerate(idxs)
                )
                # A fresh permit catalogue per subset: permits are consumed
                # inside one tree, never carried across brute-force attempts.
                # Every distinct permit binding yields a distinct tree.
                for tree in _try_build_subset(
                    case, labelled, root, receiver_set, topic,
                    dict(permits_by_id)
                ):
                    valid.append(tree)

    # Compare on labelled edges plus the permit set: both oracles use the
    # same identity even though they construct trees through different code.
    def identity(tree: BuiltTree):
        return tree.canonical_edge_seq, tuple(sorted(tree.used_permits))

    unique = {}
    for tree in valid:
        unique[identity(tree)] = tree
    valid = sorted(unique.values(), key=tree_sort_key)

    main_trees, capped = enumerate_trees(case)
    main_sigs = {identity(t) for t in main_trees}
    brute_sigs = set(unique)
    agrees = main_sigs == brute_sigs and not capped

    # Independent feasibility conclusion via brute-force pair scan.
    brute_feasible = False
    brute_best = None
    for i, ta in enumerate(valid):
        for tb in valid[i + 1:]:
            if pair_feasible(case, ta, tb) is None:
                continue
            brute_feasible = True
            ordered = sorted((ta, tb), key=tree_sort_key)
            key = pair_cost(ta, tb, case) + (
                ordered[0].canonical_edge_seq,
                ordered[0].canonical_transform_seq,
                ordered[1].canonical_edge_seq,
                ordered[1].canonical_transform_seq,
            )
            if brute_best is None or key < brute_best[0]:
                brute_best = (key, ordered)
    result = plan(case)
    if brute_feasible and result.feasible:
        cost_matches = list(brute_best[0][:3]) == list(result.cost)
    else:
        cost_matches = brute_feasible == result.feasible
    return {
        "applied": True,
        "subsets_scanned": subsets_scanned,
        "brute_force_tree_count": len(valid),
        "enumerator_tree_count": len(main_trees),
        "tree_sets_agree": agrees,
        "brute_force_feasible": brute_feasible,
        "planner_feasible": result.feasible,
        "feasibility_agrees": brute_feasible == result.feasible,
        "optimum_cost_agrees": cost_matches,
        "brute_force_best_cost": list(brute_best[0][:3]) if brute_best else None,
        "planner_cost": list(result.cost) if result.cost else None,
    }


def _try_build_subset(
    case: Case,
    labelled: tuple[tuple, ...],
    root: str,
    receiver_set: set[str],
    topic,
    permits_by_id: dict[str, Permit],
) -> list[BuiltTree]:
    """All valid trees for one labelled edge subset.

    A single subset can produce several trees when more than one permit
    authorizes the same label change; each binding is enumerated explicitly.
    """
    edges = []
    seen_dst: set[str] = set()
    for edge, label in labelled:
        if edge.dst == root or edge.dst in seen_dst:
            return []
        if edge.max_classification < topic.classification:
            return []
        seen_dst.add(edge.dst)
        edges.append((edge, label))

    # Reachability from root.
    adj: dict[str, list] = {nid: [] for nid in case.nodes}
    for edge, label in edges:
        adj[edge.src].append((edge, label))
    reached = {root}
    queue = [root]
    while queue:
        u = queue.pop(0)
        for edge, label in adj[u]:
            if edge.dst not in reached:
                reached.add(edge.dst)
                queue.append(edge.dst)
    if not receiver_set <= reached:
        return []
    if any(edge.dst not in reached for edge, _ in edges):
        return []
    # Leaf rule mirrors the enumerator: a node is a leaf only when the
    # selected edge set actually terminates there.
    destinations = {edge.dst for edge, _ in edges}
    has_child = {edge.src for edge, _ in edges}
    for node_id in destinations:
        if node_id not in has_child and node_id not in receiver_set:
            return []

    # Derive the required label changes in BFS order.  The root may fan out
    # both plaintext edges (no transform) and ciphertext edges (P->C each),
    # so the change is judged per edge against the node's inbound label.
    in_label = {edge.dst: label for edge, label in edges}
    children: dict[str, list] = {nid: [] for nid in case.nodes}
    for edge, label in edges:
        children[edge.src].append((edge, label))
    for adj_list in children.values():
        adj_list.sort(key=lambda x: (x[0].dst, x[0].id))

    change_points: list[tuple[str, str, str]] = []  # (node, from, to)
    bfs = [root]
    head = 0
    while head < len(bfs):
        u = bfs[head]
        head += 1
        incoming = LABEL_PLAIN if u == root else in_label[u]
        for edge, label in children[u]:
            if incoming != label:
                change_points.append((u, incoming, label))
            bfs.append(edge.dst)

    options_per_point = []
    for u, frm, to in change_points:
        choices = sorted(
            p.id for p in permits_by_id.values()
            if p.node == u and p.from_label == frm and p.to_label == to
            and p.topic == topic.id
        )
        if not choices:
            return []
        options_per_point.append(choices)

    trees: list[BuiltTree] = []
    msg = case.message
    for combo in itertools.product(*options_per_point):
        if len(set(combo)) != len(combo):
            continue  # one permit cannot be consumed twice inside one tree
        transform_specs = tuple(
            TransformSpec(node=u, from_label=frm, to_label=to, permit_id=pid)
            for (u, frm, to), pid in zip(change_points, combo)
        )
        spec = TreeSpec(
            tree_id="brute",
            root=root,
            edges=tuple((edge.id, label) for edge, label in edges),
            transforms=transform_specs,
        )
        fresh = dict(permits_by_id)
        tree, violations = build_tree_from_spec(
            case, spec, fresh, "crosscheck", trust_declared_permits=True
        )
        if tree is None or violations:
            continue
        if any(msg.window_latest + p.delay_max > msg.deadline
               for p in tree.paths.values()):
            continue
        trees.append(tree)
    return trees
