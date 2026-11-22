"""Synthetic case data model and strict input validation.

Every field path reported in a validation error mirrors the JSON document
(e.g. ``edges[3].delay_max``), so a rejected case can be repaired mechanically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .errors import InputError, Validator
from . import LABELS, MAX_EDGES, MAX_FAULT_DOMAINS, MAX_NODES, MAX_RECEIVERS

ROLES = ("publisher", "relay", "receiver")


@dataclass(frozen=True)
class Node:
    id: str
    role: str


@dataclass(frozen=True)
class Edge:
    id: str
    src: str
    dst: str
    allowed_labels: frozenset[str]
    max_classification: int
    delay_min: int
    delay_max: int
    fault_domain: str
    cost: int


@dataclass(frozen=True)
class Topic:
    id: str
    classification: int
    plain_allowed: frozenset[str]


@dataclass(frozen=True)
class Message:
    id: str
    topic: str
    publisher: str
    digest: str
    generation: int
    window_earliest: int
    window_latest: int
    deadline: int


@dataclass(frozen=True)
class Permit:
    id: str
    node: str
    from_label: str
    to_label: str
    topic: str
    generation: int
    version: str


@dataclass(frozen=True)
class FaultDomain:
    id: str
    edges: frozenset[str]
    nodes: frozenset[str]


@dataclass(frozen=True)
class TreeSpec:
    """A rooted tree as supplied in ``previous`` or ``baseline`` blocks."""

    tree_id: str
    root: str
    edges: tuple[tuple[str, str], ...]            # (edge_id, label)
    transforms: tuple["TransformSpec", ...]


@dataclass(frozen=True)
class TransformSpec:
    node: str
    from_label: str
    to_label: str
    permit_id: str


@dataclass(frozen=True)
class PreviousCase:
    version: str
    tree_a: TreeSpec
    tree_b: TreeSpec
    receivers: frozenset[str]
    plain_allowed: frozenset[str]
    permits: tuple[Permit, ...]
    window_earliest: int
    window_latest: int
    in_flight: tuple[tuple[str, int], ...]        # (digest, generation)


@dataclass
class Case:
    schema_version: str
    case_id: str
    version: str
    nodes: dict[str, Node]
    edges: dict[str, Edge]
    topics: dict[str, Topic]
    message: Message
    permits: tuple[Permit, ...]
    receivers: tuple[str, ...]
    fault_domains: dict[str, FaultDomain]
    previous: PreviousCase | None
    baseline: tuple[TreeSpec, TreeSpec] | None
    check_publish_time: int | None
    check_failed_domain: str | None
    # Derived adjacency, rebuilt after construction.
    out_edges: dict[str, list[Edge]] = field(default_factory=dict)
    domain_edge_masks: dict[str, int] = field(default_factory=dict)
    domain_node_masks: dict[str, int] = field(default_factory=dict)


def load_document(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise InputError(path, "file not found") from exc
    except json.JSONDecodeError as exc:
        raise InputError(path, f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}") from exc
    except OSError as exc:
        raise InputError(path, f"unreadable file: {exc}") from exc


def _is_int(value: Any) -> bool:
    # Reject bool, which is a subclass of int in Python.
    return isinstance(value, int) and not isinstance(value, bool)


def _require_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def parse_case(doc: dict[str, Any]) -> Case:
    v = Validator()
    if not isinstance(doc, dict):
        v.fail("$", "top-level JSON value must be an object")
        v.finish()

    schema_version = doc.get("schema_version")
    v.require(_require_str(schema_version), "schema_version", "must be a non-empty string")
    case_id = doc.get("case_id")
    v.require(_require_str(case_id), "case_id", "must be a non-empty string")
    version = doc.get("version")
    v.require(_require_str(version), "version", "must be a non-empty string")

    nodes = _parse_nodes(doc, v)
    node_ids = set(nodes)
    edges, edge_list = _parse_edges(doc, v, node_ids)
    topics = _parse_topics(doc, v, node_ids)
    message = _parse_message(doc, v, nodes, topics)
    fault_domains = _parse_domains(doc, v, node_ids, set(edges))
    _validate_edge_domains(edge_list, fault_domains, nodes, v)
    receivers = _parse_receivers(doc, v, nodes)
    permits = _parse_permits(doc, v, node_ids, topics, message, version)
    previous = _parse_previous(doc, v, node_ids, edges, topics, message, version)
    baseline = _parse_baseline(doc, v, node_ids, edges)
    check_publish_time, check_failed_domain = _parse_check_request(
        doc, v, message, fault_domains
    )
    v.finish()

    case = Case(
        schema_version=schema_version,
        case_id=case_id,
        version=version,
        nodes=nodes,
        edges=edges,
        topics=topics,
        message=message,
        permits=permits,
        receivers=receivers,
        fault_domains=fault_domains,
        previous=previous,
        baseline=baseline,
        check_publish_time=check_publish_time,
        check_failed_domain=check_failed_domain,
    )
    out_edges: dict[str, list[Edge]] = {nid: [] for nid in nodes}
    for edge in edge_list:
        out_edges[edge.src].append(edge)
    for adj in out_edges.values():
        adj.sort(key=lambda e: e.id)
    case.out_edges = out_edges
    case.domain_edge_masks, case.domain_node_masks = _domain_masks(
        edge_list, fault_domains
    )
    return case


def _parse_nodes(doc: dict[str, Any], v: Validator) -> dict[str, Node]:
    raw = doc.get("nodes")
    nodes: dict[str, Node] = {}
    if not v.require(isinstance(raw, list), "nodes", "must be a list"):
        return nodes
    v.require(len(raw) <= MAX_NODES, "nodes", f"at most {MAX_NODES} nodes are supported")
    publisher_count = 0
    for i, item in enumerate(raw):
        p = f"nodes[{i}]"
        if not isinstance(item, dict):
            v.fail(p, "must be an object")
            continue
        nid = item.get("id")
        role = item.get("role")
        ok_id = v.require(_require_str(nid), f"{p}.id", "must be a non-empty string")
        ok_role = v.require(role in ROLES, f"{p}.role", f"must be one of {ROLES}")
        if ok_id:
            if nid in nodes:
                v.fail(f"{p}.id", f"duplicate node id {nid!r}")
            else:
                nodes[nid] = Node(id=nid, role=role if ok_role else "relay")
            if role == "publisher":
                publisher_count += 1
    v.require(publisher_count == 1, "nodes", "exactly one publisher node is required")
    return nodes


def _parse_edges(
    doc: dict[str, Any], v: Validator, node_ids: set[str]
) -> tuple[dict[str, Edge], list[Edge]]:
    raw = doc.get("edges")
    edges: dict[str, Edge] = {}
    edge_list: list[Edge] = []
    if not v.require(isinstance(raw, list), "edges", "must be a list"):
        return edges, edge_list
    v.require(len(raw) <= MAX_EDGES, "edges", f"at most {MAX_EDGES} edges are supported")
    for i, item in enumerate(raw):
        p = f"edges[{i}]"
        if not isinstance(item, dict):
            v.fail(p, "must be an object")
            continue
        eid = item.get("id")
        src = item.get("src")
        dst = item.get("dst")
        if not v.require(_require_str(eid), f"{p}.id", "must be a non-empty string"):
            continue
        if eid in edges:
            v.fail(f"{p}.id", f"duplicate edge id {eid!r}")
        v.require(_require_str(src) and src in node_ids, f"{p}.src", "must reference a declared node")
        v.require(_require_str(dst) and dst in node_ids, f"{p}.dst", "must reference a declared node")
        if src == dst and _require_str(src):
            v.fail(f"{p}.dst", "self loops are not allowed")
        labels = item.get("allowed_labels")
        ok_labels = v.require(isinstance(labels, list) and len(labels) > 0,
                              f"{p}.allowed_labels", "must be a non-empty list")
        label_set: frozenset[str] = frozenset()
        if ok_labels:
            bad = [lab for lab in labels if lab not in LABELS]
            v.require(not bad, f"{p}.allowed_labels", f"labels must be one of {LABELS}")
            label_set = frozenset(lab for lab in labels if lab in LABELS)
            if len(label_set) != len(labels):
                v.fail(f"{p}.allowed_labels", "duplicate labels are not allowed")
        cls = item.get("max_classification")
        v.require(_is_int(cls) and cls >= 0, f"{p}.max_classification", "must be a non-negative integer")
        dmin = item.get("delay_min")
        dmax = item.get("delay_max")
        v.require(_is_int(dmin) and dmin >= 0, f"{p}.delay_min", "must be a non-negative integer")
        v.require(_is_int(dmax) and dmax >= 0, f"{p}.delay_max", "must be a non-negative integer")
        if _is_int(dmin) and _is_int(dmax) and dmin > dmax:
            v.fail(f"{p}.delay_min", "delay_min must not exceed delay_max")
        domain = item.get("fault_domain")
        v.require(_require_str(domain), f"{p}.fault_domain", "must reference a declared fault domain")
        cost = item.get("cost")
        v.require(_is_int(cost) and cost >= 0, f"{p}.cost", "must be a non-negative integer")
        if eid not in edges and _require_str(src) and _require_str(dst):
            edge = Edge(
                id=eid, src=src, dst=dst,
                allowed_labels=label_set,
                max_classification=cls if _is_int(cls) else 0,
                delay_min=dmin if _is_int(dmin) else 0,
                delay_max=dmax if _is_int(dmax) else 0,
                fault_domain=domain if _require_str(domain) else "",
                cost=cost if _is_int(cost) else 0,
            )
            edges[eid] = edge
            edge_list.append(edge)
    return edges, edge_list


def _parse_topics(doc: dict[str, Any], v: Validator, node_ids: set[str]) -> dict[str, Topic]:
    raw = doc.get("topics")
    topics: dict[str, Topic] = {}
    if not v.require(isinstance(raw, list) and len(raw) >= 1, "topics", "must be a non-empty list"):
        return topics
    for i, item in enumerate(raw):
        p = f"topics[{i}]"
        if not isinstance(item, dict):
            v.fail(p, "must be an object")
            continue
        tid = item.get("id")
        if not v.require(_require_str(tid), f"{p}.id", "must be a non-empty string"):
            continue
        if tid in topics:
            v.fail(f"{p}.id", f"duplicate topic id {tid!r}")
        cls = item.get("classification")
        v.require(_is_int(cls) and cls >= 0, f"{p}.classification", "must be a non-negative integer")
        allowed = item.get("plain_allowed")
        ok = v.require(isinstance(allowed, list), f"{p}.plain_allowed", "must be a list")
        allowed_set: set[str] = set()
        if ok:
            for j, nid in enumerate(allowed):
                if not (_require_str(nid) and nid in node_ids):
                    v.fail(f"{p}.plain_allowed[{j}]", "must reference a declared node")
                else:
                    if nid in allowed_set:
                        v.fail(f"{p}.plain_allowed[{j}]", f"duplicate node {nid!r}")
                    allowed_set.add(nid)
        topics[tid] = Topic(
            id=tid,
            classification=cls if _is_int(cls) else 0,
            plain_allowed=frozenset(allowed_set),
        )
    return topics


def _parse_message(
    doc: dict[str, Any],
    v: Validator,
    nodes: dict[str, Node],
    topics: dict[str, Topic],
) -> Message:
    raw = doc.get("message")
    dummy = Message(id="", topic="", publisher="", digest="", generation=1,
                    window_earliest=0, window_latest=0, deadline=0)
    if not v.require(isinstance(raw, dict), "message", "must be an object"):
        return dummy
    p = "message"
    mid = raw.get("id")
    v.require(_require_str(mid), f"{p}.id", "must be a non-empty string")
    topic = raw.get("topic")
    v.require(_require_str(topic) and topic in topics, f"{p}.topic", "must reference a declared topic")
    publisher = raw.get("publisher")
    ok_pub = v.require(_require_str(publisher) and publisher in nodes,
                       f"{p}.publisher", "must reference a declared node")
    if ok_pub and nodes[publisher].role != "publisher":
        v.fail(f"{p}.publisher", f"node {publisher!r} must have role 'publisher'")
    digest = raw.get("digest")
    v.require(_require_str(digest), f"{p}.digest", "must be a non-empty string")
    generation = raw.get("generation")
    v.require(_is_int(generation) and generation >= 1, f"{p}.generation", "must be a positive integer")
    window = raw.get("publish_window")
    earliest = latest = 0
    if v.require(isinstance(window, dict), f"{p}.publish_window", "must be an object"):
        earliest = window.get("earliest")
        latest = window.get("latest")
        v.require(_is_int(earliest), f"{p}.publish_window.earliest", "must be an integer")
        v.require(_is_int(latest), f"{p}.publish_window.latest", "must be an integer")
        if _is_int(earliest) and _is_int(latest) and earliest > latest:
            v.fail(f"{p}.publish_window.earliest", "window start must not exceed window end")
    deadline = raw.get("deadline")
    v.require(_is_int(deadline), f"{p}.deadline", "must be an integer")
    if _is_int(deadline) and _is_int(latest) and deadline < latest:
        v.fail(f"{p}.deadline", "deadline must not precede the publish window end")
    return Message(
        id=mid if _require_str(mid) else "",
        topic=topic if _require_str(topic) else "",
        publisher=publisher if _require_str(publisher) else "",
        digest=digest if _require_str(digest) else "",
        generation=generation if _is_int(generation) else 1,
        window_earliest=earliest if _is_int(earliest) else 0,
        window_latest=latest if _is_int(latest) else 0,
        deadline=deadline if _is_int(deadline) else 0,
    )


def _parse_domains(
    doc: dict[str, Any],
    v: Validator,
    node_ids: set[str],
    edge_ids: set[str],
) -> dict[str, FaultDomain]:
    raw = doc.get("fault_domains")
    domains: dict[str, FaultDomain] = {}
    if not v.require(isinstance(raw, list) and raw, "fault_domains", "must be a non-empty list"):
        return domains
    v.require(len(raw) <= MAX_FAULT_DOMAINS, "fault_domains",
              f"at most {MAX_FAULT_DOMAINS} fault domains are supported")
    for i, item in enumerate(raw):
        p = f"fault_domains[{i}]"
        if not isinstance(item, dict):
            v.fail(p, "must be an object")
            continue
        did = item.get("id")
        if not v.require(_require_str(did), f"{p}.id", "must be a non-empty string"):
            continue
        if did in domains:
            v.fail(f"{p}.id", f"duplicate fault domain id {did!r}")
        d_edges = item.get("edges", [])
        d_nodes = item.get("nodes", [])
        v.require(isinstance(d_edges, list), f"{p}.edges", "must be a list")
        v.require(isinstance(d_nodes, list), f"{p}.nodes", "must be a list")
        edge_set: set[str] = set()
        node_set: set[str] = set()
        if isinstance(d_edges, list):
            for j, eid in enumerate(d_edges):
                if not (_require_str(eid) and eid in edge_ids):
                    v.fail(f"{p}.edges[{j}]", "must reference a declared edge")
                elif eid in edge_set:
                    v.fail(f"{p}.edges[{j}]", f"duplicate edge {eid!r}")
                else:
                    edge_set.add(eid)
        if isinstance(d_nodes, list):
            for j, nid in enumerate(d_nodes):
                if not (_require_str(nid) and nid in node_ids):
                    v.fail(f"{p}.nodes[{j}]", "must reference a declared node")
                elif nid in node_set:
                    v.fail(f"{p}.nodes[{j}]", f"duplicate node {nid!r}")
                else:
                    node_set.add(nid)
        if not edge_set and not node_set:
            v.fail(p, "fault domain must contain at least one edge or transit node")
        domains[did] = FaultDomain(id=did, edges=frozenset(edge_set),
                                   nodes=frozenset(node_set))
    return domains


def _validate_edge_domains(
    edge_list: list[Edge],
    domains: dict[str, FaultDomain],
    nodes: dict[str, Node],
    v: Validator,
) -> None:
    for i, edge in enumerate(edge_list):
        if edge.fault_domain and edge.fault_domain not in domains:
            v.fail(f"edges[{i}].fault_domain",
                   f"unknown fault domain {edge.fault_domain!r}")
        elif edge.fault_domain:
            # An edge is effectively inside its declared domain; require the
            # domain roster to list it so both views stay consistent.
            if edge.id not in domains[edge.fault_domain].edges:
                v.fail(f"edges[{i}].fault_domain",
                       f"edge {edge.id!r} declares domain {edge.fault_domain!r} "
                       "but is absent from that domain's edge roster")
    for i, domain in enumerate(domains.values()):
        for nid in sorted(domain.nodes):
            if nid in nodes and nodes[nid].role != "relay":
                v.fail(f"fault_domains[{i}].nodes",
                       f"only relay nodes may sit inside a fault domain; {nid!r} is {nodes[nid].role}")


def _parse_receivers(doc: dict[str, Any], v: Validator, nodes: dict[str, Node]) -> tuple[str, ...]:
    raw = doc.get("receivers")
    if not v.require(isinstance(raw, list) and raw, "receivers", "must be a non-empty list"):
        return ()
    v.require(len(raw) <= MAX_RECEIVERS, "receivers", f"at most {MAX_RECEIVERS} receivers are supported")
    receivers: list[str] = []
    for i, nid in enumerate(raw):
        p = f"receivers[{i}]"
        if not (_require_str(nid) and nid in nodes):
            v.fail(p, "must reference a declared node")
            continue
        if nid in receivers:
            v.fail(p, f"duplicate receiver {nid!r}")
            continue
        if nodes[nid].role != "receiver":
            v.fail(p, f"node {nid!r} must have role 'receiver'")
        receivers.append(nid)
    return tuple(receivers)


def _parse_permits(
    doc: dict[str, Any],
    v: Validator,
    node_ids: set[str],
    topics: dict[str, Topic],
    message: Message,
    version: str,
) -> tuple[Permit, ...]:
    raw = doc.get("permits", [])
    if not v.require(isinstance(raw, list), "permits", "must be a list"):
        return ()
    permits: list[Permit] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        p = f"permits[{i}]"
        if not isinstance(item, dict):
            v.fail(p, "must be an object")
            continue
        pid = item.get("id")
        if not v.require(_require_str(pid), f"{p}.id", "must be a non-empty string"):
            continue
        if pid in seen:
            v.fail(f"{p}.id", f"duplicate permit id {pid!r}")
        seen.add(pid)
        node = item.get("node")
        v.require(_require_str(node) and node in node_ids, f"{p}.node", "must reference a declared node")
        frm = item.get("from_label")
        to = item.get("to_label")
        v.require(frm in LABELS, f"{p}.from_label", f"must be one of {LABELS}")
        v.require(to in LABELS, f"{p}.to_label", f"must be one of {LABELS}")
        if frm in LABELS and to in LABELS and frm == to:
            v.fail(p, "from_label and to_label must differ; forwarding needs no permit")
        topic = item.get("topic")
        v.require(_require_str(topic) and topic in topics, f"{p}.topic", "must reference a declared topic")
        gen = item.get("generation")
        v.require(_is_int(gen), f"{p}.generation", "must be an integer")
        if _is_int(gen) and gen != message.generation:
            v.fail(f"{p}.generation",
                   f"permit generation {gen} does not match message generation {message.generation}; mixing input versions is forbidden")
        pver = item.get("version")
        v.require(_require_str(pver), f"{p}.version", "must be a non-empty string")
        if _require_str(pver) and pver != version:
            v.fail(f"{p}.version",
                   f"permit version {pver!r} does not match case version {version!r}; mixing input versions is forbidden")
        permits.append(Permit(
            id=pid, node=node if _require_str(node) else "",
            from_label=frm if frm in LABELS else "C",
            to_label=to if to in LABELS else "P",
            topic=topic if _require_str(topic) else "",
            generation=gen if _is_int(gen) else 0,
            version=pver if _require_str(pver) else "",
        ))
    return tuple(permits)


def _parse_tree(
    raw: Any,
    p: str,
    v: Validator,
    node_ids: set[str],
    edges: dict[str, Edge],
    permit_index: dict[str, Permit] | None,
) -> TreeSpec | None:
    if not isinstance(raw, dict):
        v.fail(p, "must be an object")
        return None
    tid = raw.get("tree_id")
    v.require(_require_str(tid), f"{p}.tree_id", "must be a non-empty string")
    root = raw.get("root")
    v.require(_require_str(root) and root in node_ids, f"{p}.root", "must reference a declared node")
    raw_edges = raw.get("edges")
    tree_edges: list[tuple[str, str]] = []
    if not v.require(isinstance(raw_edges, list) and raw_edges, f"{p}.edges",
                     "must be a non-empty list"):
        return None
    used_edges: set[str] = set()
    for i, item in enumerate(raw_edges):
        ep = f"{p}.edges[{i}]"
        if not isinstance(item, dict):
            v.fail(ep, "must be an object")
            continue
        eid = item.get("edge_id")
        label = item.get("label")
        if not (_require_str(eid) and eid in edges):
            v.fail(f"{ep}.edge_id", "must reference a declared edge")
            continue
        if eid in used_edges:
            v.fail(f"{ep}.edge_id", f"edge {eid!r} is used more than once in the tree")
        used_edges.add(eid)
        v.require(label in LABELS, f"{ep}.label", f"must be one of {LABELS}")
        if label in LABELS and label not in edges[eid].allowed_labels:
            v.fail(f"{ep}.label", f"edge {eid!r} does not allow label {label!r}")
        tree_edges.append((eid, label if label in LABELS else "C"))
    raw_transforms = raw.get("transforms", [])
    transforms: list[TransformSpec] = []
    if v.require(isinstance(raw_transforms, list), f"{p}.transforms", "must be a list"):
        for i, item in enumerate(raw_transforms):
            tp = f"{p}.transforms[{i}]"
            if not isinstance(item, dict):
                v.fail(tp, "must be an object")
                continue
            node = item.get("node")
            frm = item.get("from_label")
            to = item.get("to_label")
            pid = item.get("permit_id")
            v.require(_require_str(node) and node in node_ids, f"{tp}.node",
                      "must reference a declared node")
            v.require(frm in LABELS, f"{tp}.from_label", f"must be one of {LABELS}")
            v.require(to in LABELS, f"{tp}.to_label", f"must be one of {LABELS}")
            if frm in LABELS and to in LABELS and frm == to:
                v.fail(tp, "from_label and to_label must differ")
            v.require(_require_str(pid), f"{tp}.permit_id", "must be a non-empty string")
            if permit_index is not None and _require_str(pid):
                permit = permit_index.get(pid)
                if permit is None:
                    v.fail(f"{tp}.permit_id", "permit is not part of this input version")
                else:
                    if _require_str(node) and permit.node != node:
                        v.fail(f"{tp}.permit_id", f"permit {pid!r} is bound to node {permit.node!r}")
                    if frm in LABELS and (permit.from_label, permit.to_label) != (frm, to):
                        v.fail(f"{tp}.permit_id",
                               f"permit {pid!r} authorises {permit.from_label}->{permit.to_label}, not {frm}->{to}")
            transforms.append(TransformSpec(
                node=node if _require_str(node) else "",
                from_label=frm if frm in LABELS else "C",
                to_label=to if to in LABELS else "P",
                permit_id=pid if _require_str(pid) else "",
            ))
    return TreeSpec(
        tree_id=tid if _require_str(tid) else "",
        root=root if _require_str(root) else "",
        edges=tuple(tree_edges),
        transforms=tuple(transforms),
    )


def _parse_previous(
    doc: dict[str, Any],
    v: Validator,
    node_ids: set[str],
    edges: dict[str, Edge],
    topics: dict[str, Topic],
    message: Message,
    version: str,
) -> PreviousCase | None:
    raw = doc.get("previous")
    if raw is None:
        return None
    if not v.require(isinstance(raw, dict), "previous", "must be an object"):
        return None
    p = "previous"
    old_version = raw.get("version")
    v.require(_require_str(old_version), f"{p}.version", "must be a non-empty string")
    if _require_str(old_version) and old_version == version:
        v.fail(f"{p}.version", "previous version must differ from the current version")
    raw_permits = raw.get("permits", [])
    old_permits: list[Permit] = []
    permit_index: dict[str, Permit] = {}
    if v.require(isinstance(raw_permits, list), f"{p}.permits", "must be a list"):
        for i, item in enumerate(raw_permits):
            pp = f"{p}.permits[{i}]"
            if not isinstance(item, dict):
                v.fail(pp, "must be an object")
                continue
            pid = item.get("id")
            node = item.get("node")
            frm = item.get("from_label")
            to = item.get("to_label")
            topic = item.get("topic")
            gen = item.get("generation")
            pver = item.get("version")
            v.require(_require_str(pid), f"{pp}.id", "must be a non-empty string")
            v.require(_require_str(node) and node in node_ids, f"{pp}.node",
                      "must reference a declared node")
            v.require(frm in LABELS, f"{pp}.from_label", f"must be one of {LABELS}")
            v.require(to in LABELS, f"{pp}.to_label", f"must be one of {LABELS}")
            v.require(_require_str(topic) and topic in topics, f"{pp}.topic",
                      "must reference a declared topic")
            v.require(_is_int(gen), f"{pp}.generation", "must be an integer")
            v.require(_require_str(pver), f"{pp}.version", "must be a non-empty string")
            if _require_str(pver) and pver != old_version:
                v.fail(f"{pp}.version", "old permit must carry the previous input version")
            permit = Permit(
                id=pid if _require_str(pid) else "",
                node=node if _require_str(node) else "",
                from_label=frm if frm in LABELS else "C",
                to_label=to if to in LABELS else "P",
                topic=topic if _require_str(topic) else "",
                generation=gen if _is_int(gen) else 0,
                version=pver if _require_str(pver) else "",
            )
            old_permits.append(permit)
            permit_index[permit.id] = permit
    tree_a = _parse_tree(raw.get("tree_a"), f"{p}.tree_a", v, node_ids, edges, permit_index)
    tree_b = _parse_tree(raw.get("tree_b"), f"{p}.tree_b", v, node_ids, edges, permit_index)
    raw_receivers = raw.get("receivers")
    old_receivers: set[str] = set()
    if v.require(isinstance(raw_receivers, list) and raw_receivers,
                 f"{p}.receivers", "must be a non-empty list"):
        for i, nid in enumerate(raw_receivers):
            if _require_str(nid) and nid in node_ids:
                old_receivers.add(nid)
            else:
                v.fail(f"{p}.receivers[{i}]", "must reference a declared node")
    raw_allowed = raw.get("plain_allowed")
    old_allowed: set[str] = set()
    if v.require(isinstance(raw_allowed, list) and raw_allowed,
                 f"{p}.plain_allowed", "must be a non-empty list"):
        for i, nid in enumerate(raw_allowed):
            if _require_str(nid) and nid in node_ids:
                old_allowed.add(nid)
            else:
                v.fail(f"{p}.plain_allowed[{i}]", "must reference a declared node")
    window = raw.get("publish_window")
    earliest = latest = 0
    if v.require(isinstance(window, dict), f"{p}.publish_window", "must be an object"):
        earliest = window.get("earliest")
        latest = window.get("latest")
        v.require(_is_int(earliest), f"{p}.publish_window.earliest", "must be an integer")
        v.require(_is_int(latest), f"{p}.publish_window.latest", "must be an integer")
        if _is_int(earliest) and _is_int(latest) and earliest > latest:
            v.fail(f"{p}.publish_window.earliest", "window start must not exceed window end")
    in_flight: list[tuple[str, int]] = []
    raw_flight = raw.get("in_flight", [])
    if v.require(isinstance(raw_flight, list), f"{p}.in_flight", "must be a list"):
        for i, item in enumerate(raw_flight):
            fp = f"{p}.in_flight[{i}]"
            if not isinstance(item, dict):
                v.fail(fp, "must be an object")
                continue
            digest = item.get("digest")
            gen = item.get("generation")
            v.require(_require_str(digest), f"{fp}.digest", "must be a non-empty string")
            v.require(_is_int(gen) and gen >= 1, f"{fp}.generation", "must be a positive integer")
            if _require_str(digest) and _is_int(gen):
                in_flight.append((digest, gen))
            if _is_int(gen) and gen >= message.generation:
                v.fail(f"{fp}.generation", "in-flight messages must belong to an older generation")
    if tree_a is None or tree_b is None:
        return None
    return PreviousCase(
        version=old_version if _require_str(old_version) else "",
        tree_a=tree_a,
        tree_b=tree_b,
        receivers=frozenset(old_receivers),
        plain_allowed=frozenset(old_allowed),
        permits=tuple(old_permits),
        window_earliest=earliest if _is_int(earliest) else 0,
        window_latest=latest if _is_int(latest) else 0,
        in_flight=tuple(in_flight),
    )


def _parse_baseline(
    doc: dict[str, Any],
    v: Validator,
    node_ids: set[str],
    edges: dict[str, Edge],
) -> tuple[TreeSpec, TreeSpec] | None:
    raw = doc.get("baseline")
    if raw is None:
        return None
    if not v.require(isinstance(raw, dict), "baseline", "must be an object"):
        return None
    # Baseline trees must only use current-version permits; that binding check
    # is performed by the verifier, which owns current-version permit semantics.
    tree_a = _parse_tree(raw.get("tree_a"), "baseline.tree_a", v, node_ids, edges, None)
    tree_b = _parse_tree(raw.get("tree_b"), "baseline.tree_b", v, node_ids, edges, None)
    if tree_a is None or tree_b is None:
        return None
    return tree_a, tree_b


def _parse_check_request(
    doc: dict[str, Any],
    v: Validator,
    message: Message,
    domains: dict[str, FaultDomain],
) -> tuple[int | None, str | None]:
    raw = doc.get("check_request")
    if raw is None:
        return None, None
    if not v.require(isinstance(raw, dict), "check_request", "must be an object"):
        return None, None
    publish_time = raw.get("publish_time")
    failed_domain = raw.get("failed_domain", None)
    v.require(_is_int(publish_time), "check_request.publish_time", "must be an integer")
    if _is_int(publish_time) and not (
        message.window_earliest <= publish_time <= message.window_latest
    ):
        v.fail("check_request.publish_time",
               f"must lie inside the publish window [{message.window_earliest}, {message.window_latest}]")
    if failed_domain is not None:
        v.require(_require_str(failed_domain) and failed_domain in domains,
                  "check_request.failed_domain", "must reference a declared fault domain or be null")
    return (
        publish_time if _is_int(publish_time) else None,
        failed_domain if failed_domain is None or _require_str(failed_domain) else None,
    )


def _domain_masks(
    edge_list: list[Edge], domains: dict[str, FaultDomain]
) -> tuple[dict[str, int], dict[str, int]]:
    edge_index = {edge.id: i for i, edge in enumerate(edge_list)}
    edge_masks: dict[str, int] = {}
    for did, domain in domains.items():
        edge_masks[did] = sum(1 << edge_index[eid] for eid in domain.edges)
    # Node masks use a stable per-case index derived from sorted node ids.
    all_nodes = sorted({n for d in domains.values() for n in d.nodes})
    node_index = {nid: i for i, nid in enumerate(all_nodes)}
    node_masks: dict[str, int] = {}
    for did, domain in domains.items():
        node_masks[did] = sum(1 << node_index[nid] for nid in domain.nodes)
    return edge_masks, node_masks
