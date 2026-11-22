"""Rooted-tree semantics, metrics, and exhaustive arborescence enumeration.

A tree is represented by its labelled incoming edge for every non-root node.
Two encapsulation labels exist (``C`` ciphertext, ``P`` plaintext); see
``multicast_guard/__init__.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import LABEL_PLAIN
from .model import Case, Edge, Permit, TreeSpec

# Hard, reproducible cap on retained candidates.  Exhaustiveness is guaranteed
# up to this cap; the published synthetic size (18/32) stays below it once the
# structural prunings below apply.  Small cases enumerate fully and report
# ``capped = false``, which the independent brute-force cross-check relies on.
ENUM_TREE_CAP = 5_000


def _reverse_receiver_reach(case: Case) -> set[str]:
    """Nodes from which at least one listed receiver is reachable."""
    rev: dict[str, list[str]] = {nid: [] for nid in case.nodes}
    for edge in case.edges.values():
        rev[edge.dst].append(edge.src)
    good: set[str] = set()
    stack = list(case.receivers)
    while stack:
        u = stack.pop()
        if u in good:
            continue
        good.add(u)
        stack.extend(rev[u])
    return good


@dataclass
class Violation:
    """A single ordering-stable rule violation."""

    order: tuple
    point: str
    reason: str
    node: str | None = None
    edge_id: str | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {"point": self.point, "reason": self.reason}
        if self.node is not None:
            out["node"] = self.node
        if self.edge_id is not None:
            out["edge_id"] = self.edge_id
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class BuiltTree:
    tree_id: str
    root: str
    # node -> labelled incoming edge (the root has no entry)
    parent_edge: dict[str, Edge]
    in_label: dict[str, str]
    # (node, from_label, to_label, permit_id)
    transforms: tuple[tuple[str, str, str, str], ...]
    edges: tuple[Edge, ...]
    edge_labels: dict[str, str]
    used_permits: frozenset[str]
    # receiver -> ordered path payload
    paths: dict[str, PathInfo]
    edge_cost: int
    transform_count: int
    worst_max_arrival: int
    # canonical serialization payloads, computed once
    canonical_edge_seq: tuple[tuple[str, str], ...]
    canonical_transform_seq: tuple[tuple[str, str, str], ...]


@dataclass
class PathInfo:
    receiver: str
    node_path: tuple[str, ...]
    edge_path: tuple[str, ...]
    label_path: tuple[str, ...]
    delay_min: int
    delay_max: int
    # bit i set when the path touches fault domain i (edge or transit node)
    domain_mask: int
    transit_nodes: frozenset[str]


# --------------------------------------------------------------------------- #
# Tree construction from a supplied spec (baseline / previous blocks).
# --------------------------------------------------------------------------- #

def build_tree_from_spec(
    case: Case,
    spec: TreeSpec,
    permits_by_id: dict[str, Permit],
    tree_point: str,
    check_declared: bool = True,
    trust_declared_permits: bool = False,
    expected_version: str | None = None,
    expected_generation: int | None = None,
) -> tuple[BuiltTree | None, list[Violation]]:
    """Validate every structural and authorization rule of a supplied tree.

    When ``check_declared`` is False the caller does not provide a transform
    list; the transforms forced by the edge labels are simply derived.

    When ``trust_declared_permits`` is True the spec's transform list is the
    binding to validate (used by the independent brute-force oracle, which
    enumerates permit assignments itself); otherwise the smallest-id matching
    permit is auto-selected and the declared list must equal that derivation.

    ``expected_version`` / ``expected_generation`` pin the input version the
    permits must belong to (previous-version audits use the old values).
    """
    want_version = case.version if expected_version is None else expected_version
    want_generation = (case.message.generation if expected_generation is None
                       else expected_generation)
    violations: list[Violation] = []
    topic = case.topics[case.message.topic]
    root = spec.root

    parent_edge: dict[str, Edge] = {}
    in_label: dict[str, str] = {}
    edge_labels: dict[str, str] = {}
    used_edges: set[str] = set()
    order_counter = 0

    for i, (eid, label) in enumerate(spec.edges):
        point = f"{tree_point}.edges[{i}]"
        if eid not in case.edges:  # structural validation normally catches this
            violations.append(Violation((order_counter,), point,
                                        "edge is not part of this input version",
                                        edge_id=eid))
            order_counter += 1
            continue
        edge = case.edges[eid]
        if eid in used_edges:
            violations.append(Violation((order_counter,), point,
                                        "edge used twice inside one tree", edge_id=eid))
            order_counter += 1
            continue
        used_edges.add(eid)
        if label not in edge.allowed_labels:
            violations.append(Violation((order_counter,), point,
                                        f"edge does not allow encapsulation label {label!r}",
                                        node=edge.dst, edge_id=eid))
            order_counter += 1
        if edge.max_classification < topic.classification:
            violations.append(Violation((order_counter,), point,
                                        f"edge clearance {edge.max_classification} below topic "
                                        f"classification {topic.classification}",
                                        node=edge.dst, edge_id=eid))
            order_counter += 1
        if edge.dst in parent_edge:
            violations.append(Violation((order_counter,), point,
                                        f"node {edge.dst!r} has two incoming edges",
                                        node=edge.dst, edge_id=eid))
            order_counter += 1
            continue
        parent_edge[edge.dst] = edge
        in_label[edge.dst] = label
        edge_labels[eid] = label

    if violations:
        return None, violations

    # Reachability / arborescence check from the root, canonical BFS order.
    children: dict[str, list[Edge]] = {nid: [] for nid in case.nodes}
    for edge in parent_edge.values():
        children[edge.src].append(edge)
    for adj in children.values():
        adj.sort(key=lambda e: (e.dst, e.id))

    reached: set[str] = set()
    bfs_order: list[str] = []
    queue = [root]
    reached.add(root)
    head = 0
    while head < len(queue):
        u = queue[head]
        head += 1
        bfs_order.append(u)
        for edge in children[u]:
            if edge.dst in reached:
                violations.append(Violation(
                    (head,), f"{tree_point}.edge:{edge.id}",
                    "edge would create a cycle or re-attach a reached node",
                    node=edge.dst, edge_id=edge.id))
                continue
            reached.add(edge.dst)
            queue.append(edge.dst)
    if violations:
        return None, violations

    orphaned = sorted(set(parent_edge) - reached)
    for nid in orphaned:
        violations.append(Violation((len(bfs_order),), tree_point,
                                    f"node {nid!r} is disconnected from root {root!r}",
                                    node=nid))
    if violations:
        return None, violations

    # Transform / authorization / plaintext-visibility rules, root outward.
    used_permits: set[str] = set()
    derived_transforms: list[tuple[str, str, str, str]] = []

    if trust_declared_permits:
        declared_lookup: dict[tuple[str, str, str], list[str]] = {}
        for t in spec.transforms:
            declared_lookup.setdefault(
                (t.node, t.from_label, t.to_label), []
            ).append(t.permit_id)
        for ids in declared_lookup.values():
            if len(ids) != len(set(ids)):
                violations.append(Violation(
                    (10**9,), f"{tree_point}.transforms",
                    "a single permit is declared more than once inside one tree"))

    def _take_permit(u: str, frm: str, to: str, order_key: tuple,
                     edge_id: str | None) -> str | None:
        if trust_declared_permits:
            pool = declared_lookup.get((u, frm, to))
            if not pool:
                violations.append(Violation(
                    order_key, f"{tree_point}.edge:{edge_id}",
                    f"encapsulation change {frm}->{to} has no declared permit at node",
                    node=u, edge_id=edge_id))
                return None
            pid = pool.pop(0)
            permit = permits_by_id.get(pid)
            if permit is None or permit.node != u or (
                permit.from_label, permit.to_label) != (frm, to) or (
                permit.topic != topic.id
            ):
                violations.append(Violation(
                    order_key, f"{tree_point}.transforms",
                    f"declared permit {pid!r} does not authorize {u} {frm}->{to}",
                    node=u, edge_id=edge_id))
                return None
            if pid in used_permits:
                violations.append(Violation(
                    order_key, f"{tree_point}.transforms",
                    f"permit {pid!r} is consumed twice inside one tree",
                    node=u, edge_id=edge_id))
                return None
            used_permits.add(pid)
            return pid
        permit = _consume_permit(permits_by_id, used_permits, u, frm, to, topic.id)
        if permit is None:
            violations.append(Violation(
                order_key, f"{tree_point}.edge:{edge_id}",
                f"encapsulation change {frm}->{to} lacks an unused permit at node",
                node=u, edge_id=edge_id))
            return None
        return permit.id

    for depth, u in enumerate(bfs_order):
        if u == root:
            # The publisher originates plaintext: it sees P and must be allowed.
            if root not in topic.plain_allowed:
                violations.append(Violation(
                    (depth, 0), f"{tree_point}.root",
                    "publisher sees plaintext but is absent from the topic plaintext permission set",
                    node=root))
            for k, edge in enumerate(children[u]):
                label = in_label[edge.dst]
                if label == LABEL_PLAIN:
                    continue
                # Emitting ciphertext changes form: requires a P->C permit.
                pid = _take_permit(u, LABEL_PLAIN, label,
                                   (depth, 1 + k), edge.id)
                if pid is not None:
                    derived_transforms.append((u, LABEL_PLAIN, label, pid))
            continue

        incoming = in_label[u]
        # Plaintext visibility: a node that receives P is inside the plaintext
        # sphere whether or not it is a named receiver, and must be permitted.
        if incoming == LABEL_PLAIN and u not in topic.plain_allowed:
            violations.append(Violation(
                (depth, 0), f"{tree_point}.node:{u}",
                "node receives plaintext but is absent from the topic plaintext permission set",
                node=u, edge_id=parent_edge[u].id))
        for k, edge in enumerate(children[u]):
            label = in_label[edge.dst]
            if label != incoming:
                pid = _take_permit(u, incoming, label,
                                   (depth, 1 + k), edge.id)
                if pid is not None:
                    derived_transforms.append((u, incoming, label, pid))
            if label == LABEL_PLAIN and edge.dst not in topic.plain_allowed:
                violations.append(Violation(
                    (depth, 100 + k), f"{tree_point}.edge:{edge.id}",
                    "downstream node would receive plaintext without topic permission",
                    node=edge.dst, edge_id=edge.id))
    if trust_declared_permits:
        leftover = [pid for pool in declared_lookup.values() for pid in pool]
        if leftover:
            violations.append(Violation(
                (10**9,), f"{tree_point}.transforms",
                "declared permits do not correspond to any edge-label change",
                detail={"unused_permit_ids": sorted(leftover)}))
    if violations:
        return None, sorted(violations, key=lambda x: x.order)

    # The declared transform list must describe exactly the derived changes.
    if check_declared and not trust_declared_permits:
        declared = sorted(
            (t.node, t.from_label, t.to_label, t.permit_id) for t in spec.transforms
        )
        if declared != sorted(derived_transforms):
            violations.append(Violation(
                (10**9,), f"{tree_point}.transforms",
                "declared transform list does not match the encapsulation changes forced by the edges",
                detail={"declared": declared, "required": sorted(derived_transforms)}))
            return None, violations
    for permit_id in used_permits:
        permit = permits_by_id[permit_id]
        if permit.generation != want_generation or permit.version != want_version:
            violations.append(Violation(
                (10**9,), f"{tree_point}.transforms",
                f"permit {permit_id!r} belongs to another input version/generation",
                detail={"permit_version": permit.version,
                        "permit_generation": permit.generation,
                        "expected_version": want_version,
                        "expected_generation": want_generation}))
    if violations:
        return None, violations

    tree = _finalize_tree(spec.tree_id, root, parent_edge, in_label,
                          tuple(sorted(derived_transforms)), edge_labels,
                          frozenset(used_permits), case)

    # Leaf rule: unlisted sites may never be leaves.  Only nodes the tree
    # actually reaches participate; disconnected case nodes are irrelevant.
    receiver_set = set(case.receivers)
    for node_id in bfs_order:
        adj = children[node_id]
        if not adj and node_id != root and node_id not in receiver_set:
            violations.append(Violation(
                (10**9, node_id), f"{tree_point}.node:{node_id}",
                "non-receiver site is a leaf; unlisted sites cannot terminate a tree",
                node=node_id))
    missing = sorted(receiver_set - set(tree.paths))
    for nid in missing:
        violations.append(Violation(
            (10**9, nid), tree_point,
            f"receiver {nid!r} is not reachable on this tree", node=nid))
    if violations:
        return None, violations
    return tree, []


def _consume_permit(
    permits_by_id: dict[str, Permit],
    used: set[str],
    node: str,
    from_label: str,
    to_label: str,
    topic_id: str,
) -> Permit | None:
    """Smallest-id unused matching permit: makes every result reproducible."""
    candidates = [
        p for p in permits_by_id.values()
        if p.id not in used and p.node == node
        and p.from_label == from_label and p.to_label == to_label
        and p.topic == topic_id
    ]
    if not candidates:
        return None
    permit = min(candidates, key=lambda p: p.id)
    used.add(permit.id)
    return permit


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def _finalize_tree(
    tree_id: str,
    root: str,
    parent_edge: dict[str, Edge],
    in_label: dict[str, str],
    transforms: tuple[tuple[str, str, str, str], ...],
    edge_labels: dict[str, str],
    used_permits: frozenset[str],
    case: Case,
) -> BuiltTree:
    edges = tuple(sorted(parent_edge.values(), key=lambda e: e.id))
    domain_index = {did: i for i, did in enumerate(sorted(case.fault_domains))}
    edge_domain_bit = {
        eid: 1 << domain_index[did]
        for did in case.fault_domains
        for eid in case.fault_domains[did].edges
    }
    node_domain_bit = {
        nid: 1 << domain_index[did]
        for did in case.fault_domains
        for nid in case.fault_domains[did].nodes
    }

    paths: dict[str, PathInfo] = {}
    worst = 0
    for receiver in case.receivers:
        node_path = [receiver]
        edge_path: list[str] = []
        label_path: list[str] = []
        dmin = dmax = 0
        mask = 0
        cur = receiver
        while cur != root:
            edge = parent_edge.get(cur)
            if edge is None:
                break
            edge_path.append(edge.id)
            label_path.append(in_label[cur])
            dmin += edge.delay_min
            dmax += edge.delay_max
            mask |= edge_domain_bit.get(edge.id, 0)
            cur = edge.src
            node_path.append(cur)
        if cur != root:
            continue
        node_path.reverse()
        edge_path.reverse()
        label_path.reverse()
        transit = frozenset(node_path[1:-1]) if len(node_path) > 1 else frozenset()
        for nid in transit:
            mask |= node_domain_bit.get(nid, 0)
        paths[receiver] = PathInfo(
            receiver=receiver,
            node_path=tuple(node_path),
            edge_path=tuple(edge_path),
            label_path=tuple(label_path),
            delay_min=dmin,
            delay_max=dmax,
            domain_mask=mask,
            transit_nodes=transit,
        )
        worst = max(worst, dmax)

    canonical_edge_seq = tuple(
        sorted((e.id, edge_labels[e.id]) for e in edges)
    )
    canonical_transform_seq = tuple(sorted(transforms))
    return BuiltTree(
        tree_id=tree_id,
        root=root,
        parent_edge=dict(parent_edge),
        in_label=dict(in_label),
        transforms=transforms,
        edges=edges,
        edge_labels=dict(edge_labels),
        used_permits=used_permits,
        paths=paths,
        edge_cost=sum(e.cost for e in edges),
        transform_count=len(transforms),
        worst_max_arrival=worst,
        canonical_edge_seq=canonical_edge_seq,
        canonical_transform_seq=canonical_transform_seq,
    )


def deadline_ok(tree: BuiltTree, case: Case) -> bool:
    """Worst-case arrival (latest publish, every edge at delay_max) is on time."""
    msg = case.message
    return all(
        msg.window_latest + path.delay_max <= msg.deadline
        for path in tree.paths.values()
    )


def arrival_window(path: PathInfo, publish_time: int) -> tuple[int, int]:
    return publish_time + path.delay_min, publish_time + path.delay_max


# --------------------------------------------------------------------------- #
# Exhaustive enumeration of candidate arborescences.
# --------------------------------------------------------------------------- #

# Above this edge count the labelled DFS would explode; the bounded
# path-union enumerator below is used instead.  Small cases keep the fully
# exact path, which the independent brute-force oracle cross-checks.
SKELETON_THRESHOLD = 12
PATH_VARIANTS = 6
UNION_BEAM = 80


def _enumerate_skeletons(case: Case) -> tuple[list[BuiltTree], bool]:
    """Bounded, deterministic candidate generation for dense full-scale inputs.

    For every receiver the K cheapest edge paths are computed with a
    deterministic Dijkstra.  A bounded beam then unions one path per receiver
    into rooted edge-set skeletons (shared prefixes merge automatically), each
    of which receives a deterministic encapsulation/permit assignment.  The
    method is reproducible and explicitly reports ``capped = True`` so callers
    know it is a bounded search rather than a proof of exhaustiveness.
    """
    msg = case.message
    topic = case.topics[msg.topic]
    root = msg.publisher
    receiver_set = set(case.receivers)
    if root not in topic.plain_allowed:
        return [], False
    permits_by_id = {p.id: p for p in case.permits}

    paths_per_receiver: dict[str, list[tuple[Edge, ...]]] = {}
    for receiver in case.receivers:
        paths_per_receiver[receiver] = _k_shortest_paths(
            case, root, receiver, topic, msg, PATH_VARIANTS
        )
    if any(not paths_per_receiver[r] for r in case.receivers):
        return [], True

    def union_domain_mask(edge_ids: frozenset[str]) -> int:
        mask = 0
        for i, did in enumerate(sorted(case.fault_domains)):
            if case.fault_domains[did].edges & edge_ids:
                mask |= 1 << i
        return mask

    # Beam over partial unions.  Diversity is enforced on the fault-domain
    # mask: for every distinct mask we keep the cheapest union, so the pool
    # spans structurally independent trees rather than cheap-but-colliding ones.
    beam: dict[frozenset[str], int] = {frozenset(): 0}
    ordered_receivers = list(case.receivers)
    for receiver in ordered_receivers:
        nxt: dict[frozenset[str], int] = {}
        best_by_mask: dict[int, tuple[int, frozenset[str]]] = {}
        for union, _old_fee in beam.items():
            for path in paths_per_receiver[receiver]:
                merged = union | {e.id for e in path}
                fee = sum(case.edges[eid].cost for eid in merged)
                mask = union_domain_mask(merged)
                incumbent = best_by_mask.get(mask)
                if incumbent is None or fee < incumbent[0] or (
                    fee == incumbent[0] and sorted(merged) < sorted(incumbent[1])
                ):
                    best_by_mask[mask] = (fee, merged)
        ranked = sorted(best_by_mask.values(), key=lambda x: (x[0], sorted(x[1])))
        for fee, merged in ranked[:UNION_BEAM]:
            nxt[merged] = fee
        beam = nxt

    edge_by_id = case.edges
    trees: list[BuiltTree] = []
    for union in beam:
        skel = tuple(sorted((edge_by_id[eid] for eid in union), key=lambda e: e.id))
        built = _label_skeleton(
            case, skel, root, receiver_set, topic, permits_by_id, msg
        )
        if built is not None:
            trees.append(built)
    # Deduplicate on the same labelled identity the exact enumerator uses.
    unique = {}
    for tree in trees:
        ident = (tree.canonical_edge_seq, tuple(sorted(tree.used_permits)))
        unique.setdefault(ident, tree)
    trees = sorted(unique.values(), key=tree_sort_key)
    # Assign stable, unique candidate ids after the final ordering.
    for i, tree in enumerate(trees):
        tree.tree_id = f"cand{i:05d}"
    return trees, True


def _k_shortest_paths(case, root, target, topic, msg, k):
    """Deterministic cheapest edge paths, diversified by fault-domain mask.

    The search repeatedly runs Dijkstra while forbidding edge sets and keeps
    the cheapest path for every distinct fault-domain mask, so a receiver
    obtains routes whose failure domains genuinely differ (A-side vs B-side)
    rather than edge-disjoint twins inside the same domain.
    """
    import heapq

    def dijkstra(removed_edges):
        dist = {root: 0}
        prev: dict[str, Edge] = {}
        heap = [(0, root)]
        while heap:
            cost, u = heapq.heappop(heap)
            if cost != dist[u]:
                continue
            if u == target:
                break
            for edge in case.out_edges[u]:
                if edge.id in removed_edges:
                    continue
                if edge.max_classification < topic.classification:
                    continue
                nd = cost + edge.cost
                if nd < dist.get(edge.dst, 10**18):
                    dist[edge.dst] = nd
                    prev[edge.dst] = edge
                    heapq.heappush(heap, (nd, edge.dst))
        if target not in dist:
            return None
        path = []
        cur = target
        while cur != root:
            edge = prev[cur]
            path.append(edge)
            cur = edge.src
        path.reverse()
        if msg.window_latest + sum(e.delay_max for e in path) > msg.deadline:
            return None
        return tuple(path)

    def domain_mask(path):
        mask = 0
        for i, did in enumerate(sorted(case.fault_domains)):
            if any(e.fault_domain == did for e in path):
                mask |= 1 << i
        return mask

    first = dijkstra(set())
    if first is None:
        return []
    best_by_mask: dict[int, tuple[Edge, ...]] = {domain_mask(first): first}
    known_edges: set[str] = {e.id for e in first}
    # Each round forbids the union of every edge already discovered, which
    # deterministically pushes Dijkstra onto the next structurally separate
    # route (A-side -> B-side) and yields a fresh fault-domain mask.
    rounds = 0
    while len(best_by_mask) < k and rounds < 4 * k + 2:
        rounds += 1
        alt = dijkstra(set(known_edges))
        if alt is None:
            break
        alt_edges = {e.id for e in alt}
        if alt_edges <= known_edges:
            break
        known_edges |= alt_edges
        best_by_mask.setdefault(domain_mask(alt), alt)
    return [best_by_mask[m] for m in sorted(best_by_mask)]


def _label_skeleton(case, skel, root, receiver_set, topic, permits_by_id, msg):
    """Deterministically assign labels/permit bindings to one edge skeleton."""
    children: dict[str, list[Edge]] = {nid: [] for nid in case.nodes}
    parent_edge: dict[str, Edge] = {}
    for edge in skel:
        children[edge.src].append(edge)
        parent_edge[edge.dst] = edge
    for adj in children.values():
        adj.sort(key=lambda e: (e.dst, e.id))

    in_label: dict[str, str] = {}
    edge_labels: dict[str, str] = {}
    used_permits: set[str] = set()
    transforms: list[tuple[str, str, str, str]] = []
    queue = [root]
    head = 0
    while head < len(queue):
        u = queue[head]
        head += 1
        incoming = LABEL_PLAIN if u == root else in_label[u]
        for edge in children[u]:
            v = edge.dst
            # Prefer keeping the inbound label (free forwarding); otherwise
            # take the cheapest authorized transform available on this edge.
            chosen = None
            if incoming in edge.allowed_labels:
                chosen = incoming
            else:
                frm = LABEL_PLAIN if u == root else incoming
                for lab in sorted(l for l in edge.allowed_labels if l != frm):
                    permit = _consume_permit(permits_by_id, used_permits, u,
                                             frm, lab, topic.id)
                    if permit is not None:
                        chosen = lab
                        transforms.append((u, frm, lab, permit.id))
                        break
            if chosen is None:
                return None
            if chosen == LABEL_PLAIN and v not in topic.plain_allowed:
                return None
            in_label[v] = chosen
            edge_labels[edge.id] = chosen
            queue.append(v)

    tree = _finalize_tree(
        f"beam{len(edge_labels):03d}", root, parent_edge, in_label,
        tuple(sorted(transforms)), edge_labels,
        frozenset(used_permits), case)
    if len(tree.paths) != len(case.receivers) or not deadline_ok(tree, case):
        return None
    return tree


def enumerate_trees(case: Case) -> tuple[list[BuiltTree], bool]:
    """Enumerate valid rooted trees covering every receiver.

    The search is an exhaustive DFS over labelled incoming edges with four
    exact prunings:

    1. reverse-reachability -- a node that cannot lead to any receiver is
       never expanded;
    2. deadline -- a prefix whose best-case arrival already misses the
       deadline is cut;
    3. plaintext sphere -- edges that would expose P to a non-permitted node
       are never taken;
    4. canonical expansion order -- every node picks its smallest viable
       outgoing edge first, so the cheapest completions are emitted before the
       reproducible candidate cap is reached.

    Returns ``(trees, capped)``.  On small inputs the enumeration is provably
    complete (``capped`` is False and the brute-force oracle agrees); the cap
    only bounds the retained candidate pool on dense full-scale inputs.
    """
    # Dense graphs use the two-stage skeleton enumerator instead.
    if len(case.edges) > SKELETON_THRESHOLD:
        return _enumerate_skeletons(case)

    msg = case.message
    topic = case.topics[msg.topic]
    root = msg.publisher
    receiver_set = set(case.receivers)
    permits_by_id = {p.id: p for p in case.permits}

    # The publisher originates plaintext, hence itself needs P permission.
    if root not in topic.plain_allowed:
        return [], False

    useful = _reverse_receiver_reach(case)
    found: dict[frozenset, BuiltTree] = {}
    seen_signatures: set[frozenset] = set()
    capped = False

    # Mutable DFS state.
    parent: dict[str, Edge] = {}
    labels: dict[str, str] = {}
    used_permits: set[str] = set()
    transforms: list[tuple[str, str, str, str]] = []
    dmin: dict[str, int] = {root: 0}
    reached: set[str] = {root}

    def emit() -> None:
        nonlocal capped
        sig = frozenset(
            [(e.id, labels[v]) for v, e in parent.items()]
            + [("permit", pid) for pid in used_permits]
        )
        if sig in seen_signatures:
            return
        seen_signatures.add(sig)
        if len(found) >= ENUM_TREE_CAP:
            capped = True
            return
        has_child: set[str] = set()
        for edge in parent.values():
            has_child.add(edge.src)
        for node_id in reached:
            if node_id not in has_child and node_id != root and node_id not in receiver_set:
                return
        tree = _finalize_tree(
            f"cand{len(found):05d}", root, dict(parent), dict(labels),
            tuple(sorted(transforms)),
            dict((e.id, labels[v]) for v, e in parent.items()),
            frozenset(used_permits), case)
        if len(tree.paths) != len(case.receivers) or not deadline_ok(tree, case):
            return
        found[sig] = tree

    def matching_permits(u: str, frm: str, to: str) -> list[str]:
        return sorted(
            p.id for p in permits_by_id.values()
            if p.id not in used_permits and p.node == u
            and p.from_label == frm and p.to_label == to and p.topic == topic.id
        )

    def dfs() -> None:
        if capped:
            return
        if receiver_set <= reached:
            emit()
        # Canonical node order keeps the search deterministic.
        for u in sorted(reached):
            incoming = None if u == root else labels[u]
            candidates: list[tuple[Edge, str, str | None]] = []
            for edge in case.out_edges[u]:
                v = edge.dst
                if v in reached or v not in useful:
                    continue
                for lab in sorted(edge.allowed_labels):
                    if u == root and lab == LABEL_PLAIN:
                        candidates.append((edge, lab, None))
                    elif u == root:
                        for pid in matching_permits(u, LABEL_PLAIN, lab):
                            candidates.append((edge, lab, pid))
                    elif lab == incoming:
                        candidates.append((edge, lab, None))
                    else:
                        for pid in matching_permits(u, incoming, lab):
                            candidates.append((edge, lab, pid))
            # Cheapest / fastest / least-privilege choices first.
            candidates.sort(key=lambda x: (
                x[0].cost, x[0].delay_max, x[0].dst, x[0].id, x[1],
                x[2] or ""))
            for edge, lab, permit_id in candidates:
                v = edge.dst
                if edge.max_classification < topic.classification:
                    continue
                new_min = dmin[u] + edge.delay_min
                if msg.window_latest + new_min > msg.deadline:
                    continue
                if lab == LABEL_PLAIN and v not in topic.plain_allowed:
                    continue
                if permit_id is not None:
                    used_permits.add(permit_id)
                parent[v] = edge
                labels[v] = lab
                reached.add(v)
                dmin[v] = new_min
                if permit_id is not None:
                    transforms.append(
                        (u, LABEL_PLAIN if u == root else incoming, lab, permit_id))
                dfs()
                if capped:
                    return
                if permit_id is not None:
                    used_permits.discard(permit_id)
                    transforms.pop()
                del parent[v]
                del labels[v]
                reached.discard(v)
                del dmin[v]

    dfs()
    trees = sorted(found.values(), key=tree_sort_key)
    return trees, capped


def tree_sort_key(tree: BuiltTree) -> tuple:
    return (
        tree.edge_cost,
        tree.transform_count,
        tree.worst_max_arrival,
        tree.canonical_edge_seq,
        tree.canonical_transform_seq,
    )
