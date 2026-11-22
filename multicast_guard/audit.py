"""Previous-version migration audit.

Old messages always travel along the old trees with the old encapsulation.
The audit re-checks those old paths against the *current* plaintext permission
set: when an old relay no longer holds P permission, the copy must be
explicitly dropped at the predecessor, before reaching that node.  Old
receivers are taken from the old directory only, so a new receiver list can
never confirm an old-generation message early.
"""

from __future__ import annotations

from dataclasses import replace

from .model import Case, PreviousCase
from .topology import BuiltTree, build_tree_from_spec


def audit_previous(case: Case) -> dict:
    previous = case.previous
    if previous is None:
        return {"present": False}

    old_permits = {p.id: p for p in previous.permits}
    current_topic = case.topics[case.message.topic]
    old_topic = replace(current_topic, plain_allowed=previous.plain_allowed)

    tree_reports = []
    built: list[BuiltTree | None] = []
    for spec in (previous.tree_a, previous.tree_b):
        tree, violations = _build_old_tree(case, spec, old_permits, old_topic)
        built.append(tree)
        tree_reports.append({
            "tree_id": spec.tree_id,
            "structurally_valid_under_old_directory": tree is not None,
            "violations": [v.to_dict() for v in violations],
        })

    # Overlap of the old and current publish acceptance windows.
    overlap_start = max(previous.window_earliest, case.message.window_earliest)
    overlap_end = min(previous.window_latest, case.message.window_latest)
    overlap = [overlap_start, overlap_end] if overlap_start <= overlap_end else None
    # The policy revision is applied at the current window's earliest instant.
    policy_time = case.message.window_earliest

    # In-flight old-generation copies; a synthetic default keeps the audit
    # explicit even when the input omits explicit in-flight digests.
    in_flight = previous.in_flight or (
        (case.message.digest, case.message.generation - 1),
    )

    receipts: dict[tuple[str, str], dict] = {}
    drops: list[dict] = []
    for tree, report in zip(built, tree_reports):
        if tree is None:
            report["path_audit"] = "skipped: old tree fails old-directory validation"
            continue
        per_tree_paths = []
        for receiver in sorted(previous.receivers):
            path = tree.paths.get(receiver)
            if path is None:
                continue
            entry = _audit_path(case, previous, tree.tree_id, path,
                                in_flight, policy_time, overlap, receipts)
            per_tree_paths.append(entry)
            if entry["disposition"] == "dropped":
                drops.append({
                    "tree_id": tree.tree_id,
                    "receiver": receiver,
                    "drop_at_node": entry["drop_at_node"],
                    "drop_at_edge": entry["drop_at_edge"],
                    "drop_reason": entry["drop_reason"],
                    "forbidden_node": entry["forbidden_node"],
                    "arrival_interval_at_drop": entry["arrival_interval_at_drop"],
                    "policy_time": entry["policy_time"],
                    "event_order": entry["event_order"],
                })
        report["path_audit"] = per_tree_paths

    receipt_list = sorted(receipts.values(), key=lambda r: (r["digest"], r["receiver"]))
    return {
        "present": True,
        "old_version": previous.version,
        "trees": tree_reports,
        "window_overlap": overlap,
        "policy_revision_time": policy_time,
        "event_order_rule": (
            "at equal instants policy changes are processed before arrivals; "
            "an arrival exactly at the deadline is accepted"
        ),
        "in_flight": [{"digest": d, "generation": g} for d, g in in_flight],
        "drops": drops,
        "receipts": receipt_list,
        "receipt_dedup_key": ["digest", "receiver"],
        "old_receiver_directory": sorted(previous.receivers),
        "new_receivers_ignored_for_old_messages": sorted(
            set(case.receivers) - previous.receivers
        ),
    }


def _build_old_tree(case: Case, spec, old_permits, old_topic):
    """Build an old tree under old-directory semantics.

    The topology is unchanged between versions.  The topic view, receiver
    directory and permit catalogue are all replaced by their previous
    versions, so old-generation validity is never judged against new lists.
    """
    topic_id = case.message.topic
    saved_topic = case.topics[topic_id]
    saved_receivers = case.receivers
    case.topics[topic_id] = old_topic
    case.receivers = tuple(sorted(case.previous.receivers))
    old_generation = case.message.generation - 1
    if case.previous.in_flight:
        old_generation = case.previous.in_flight[0][1]
    try:
        tree, violations = build_tree_from_spec(
            case, spec, old_permits, f"previous.{spec.tree_id}",
            trust_declared_permits=True,
            expected_version=case.previous.version,
            expected_generation=old_generation,
        )
    finally:
        case.topics[topic_id] = saved_topic
        case.receivers = saved_receivers
    if tree is not None and violations:
        return None, violations
    return tree, violations


def _audit_path(
    case: Case,
    previous: PreviousCase,
    tree_id: str,
    path,
    in_flight: tuple[tuple[str, int], ...],
    policy_time: int,
    overlap: list[int] | None,
    receipts: dict[tuple[str, str], dict],
) -> dict:
    current_topic = case.topics[case.message.topic]
    # Walk the path and find the first node that sees plaintext (P-labelled
    # inbound edge) but lost P permission in the current version.  Inbound
    # plaintext is visible to that node by definition: lack of an explicit
    # unseal action is not an exemption.
    drop = None
    for idx, label in enumerate(path.label_path):
        node = path.node_path[idx + 1]  # label_path[i] enters node_path[i+1]
        if label == "P" and node not in current_topic.plain_allowed:
            drop = {
                "forbidden_node": node,
                "drop_at_node": path.node_path[idx],
                "drop_at_edge": path.edge_path[idx],
                "drop_reason": "node sees inbound plaintext but lost current-version P permission",
            }
            break

    digests = [d for d, _g in in_flight]
    entry = {
        "tree_id": tree_id,
        "receiver": path.receiver,
        "node_path": list(path.node_path),
        "edge_path": list(path.edge_path),
        "label_path": list(path.label_path),
        "delay_min": path.delay_min,
        "delay_max": path.delay_max,
        "digests": digests,
    }
    if overlap is not None:
        # Latest possible branch admitted during the overlapping window.
        arrival_late_min = overlap[1] + path.delay_min
        arrival_late_max = overlap[1] + path.delay_max
        entry["late_branch_arrival_window"] = [arrival_late_min, arrival_late_max]
        entry["late_relative_to_policy"] = arrival_late_min >= policy_time
    else:
        entry["late_branch_arrival_window"] = None
        entry["late_relative_to_policy"] = None

    if drop is not None:
        cut = path.edge_path.index(drop["drop_at_edge"]) + 1
        prefix_edges = path.edge_path[:cut]
        prefix_min = sum(case.edges[e].delay_min for e in prefix_edges)
        prefix_max = sum(case.edges[e].delay_max for e in prefix_edges)
        entry.update(drop)
        entry["disposition"] = "dropped"
        entry["arrival_interval_at_drop"] = [
            previous.window_latest + prefix_min,
            previous.window_latest + prefix_max,
        ]
        entry["policy_time"] = policy_time
        entry["event_order"] = "policy_first_then_arrival"
        return entry

    entry["disposition"] = "delivered_under_old_directory"
    # Old receipts use the old receiver directory only.  Two deliveries of the
    # same digest (one per tree) produce exactly one receipt per receiver.
    for digest, generation in in_flight:
        key = (digest, path.receiver)
        arrival = [
            previous.window_latest + path.delay_min,
            previous.window_latest + path.delay_max,
        ]
        # The current deadline is the outer bound; equal-instant arrival is in.
        within_current_deadline = arrival[0] <= case.message.deadline
        if key not in receipts:
            receipts[key] = {
                "digest": digest,
                "generation": generation,
                "receiver": path.receiver,
                "tree_id_first_delivery": tree_id,
                "arrival_window": arrival,
                "within_current_deadline": within_current_deadline,
                "status": "receipt" if within_current_deadline else "late",
            }
    return entry
