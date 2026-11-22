"""Generate the frozen synthetic CASE.json fixtures.

Run once (or when a fixture definition changes):

    python tools/generate_cases.py

The generated files are the checked-in inputs the README re-verifies.  The
generator itself never touches a network or key material; every value is
hand-authored inside this module.
"""

from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASE_DIR = os.path.join(ROOT, "cases")

SCHEMA = "multicast-guard/v1"

# Common timing conventions used by every small case.
WINDOW_EARLY = 0
WINDOW_LATE = 4
DEADLINE = 20


def edge(eid, src, dst, labels, cls=5, dmin=1, dmax=2, domain="d0", cost=10):
    return {
        "id": eid,
        "src": src,
        "dst": dst,
        "allowed_labels": list(labels),
        "max_classification": cls,
        "delay_min": dmin,
        "delay_max": dmax,
        "fault_domain": domain,
        "cost": cost,
    }


def node(nid, role):
    return {"id": nid, "role": role}


def permit(pid, n, frm, to, topic, gen, ver):
    return {
        "id": pid, "node": n, "from_label": frm, "to_label": to,
        "topic": topic, "generation": gen, "version": ver,
    }


def domain(did, edges, nodes=None):
    return {"id": did, "edges": list(edges), "nodes": list(nodes or [])}


def tree_spec(tid, root, edges_with_labels, transforms):
    return {
        "tree_id": tid,
        "root": root,
        "edges": [{"edge_id": e, "label": l} for e, l in edges_with_labels],
        "transforms": transforms,
    }


def write_case(name: str, doc: dict) -> None:
    os.makedirs(CASE_DIR, exist_ok=True)
    path = os.path.join(CASE_DIR, name)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(doc, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"wrote {os.path.relpath(path, ROOT)}")


def base_doc(case_id, version, nodes, edges, receivers, plain_allowed,
             permits, domains, topic_cls=3, previous=None, baseline=None,
             check_request=None, deadline=DEADLINE,
             window=(WINDOW_EARLY, WINDOW_LATE)):
    return {
        "schema_version": SCHEMA,
        "case_id": case_id,
        "version": version,
        "nodes": nodes,
        "edges": edges,
        "topics": [{
            "id": "T1",
            "classification": topic_cls,
            "plain_allowed": sorted(plain_allowed),
        }],
        "message": {
            "id": "m1",
            "topic": "T1",
            "publisher": "P0",
            "digest": "sha256:synthetic-" + case_id,
            "generation": 2,
            "publish_window": {"earliest": window[0], "latest": window[1]},
            "deadline": deadline,
        },
        "permits": permits,
        "receivers": receivers,
        "fault_domains": domains,
        **({"previous": previous} if previous else {}),
        **({"baseline": baseline} if baseline else {}),
        **({"check_request": check_request} if check_request else {}),
    }


# --------------------------------------------------------------------------- #
# Case 1: each tree alone reaches both receivers, but they share a key domain.
# --------------------------------------------------------------------------- #

def case_shared_domain():
    nodes = [node("P0", "publisher"), node("A", "relay"), node("B", "relay"),
             node("R1", "receiver"), node("R2", "receiver"),
             node("X", "relay"), node("Y", "relay")]
    edges = [
        edge("e01", "P0", "A", "P", domain="d1"),
        edge("e02", "P0", "B", "P", domain="d2"),
        edge("e03", "A", "R1", "P", domain="d1"),
        edge("e04", "B", "R2", "P", domain="d2"),
        edge("e05", "P0", "X", "C", domain="d3"),
        edge("e06", "X", "Y", "C", domain="d3"),
        edge("e07", "Y", "R1", "C", domain="d3"),
        edge("e08", "Y", "R2", "C", domain="d3"),
        # Cross-domain spurs let one plaintext tree cover both receivers.
        edge("e09", "A", "R2", "P", domain="d2"),
        edge("e10", "B", "R1", "P", domain="d1"),
    ]
    domains = [domain("d1", ["e01", "e03", "e10"]),
               domain("d2", ["e02", "e04", "e09"]),
               domain("d3", ["e05", "e06", "e07", "e08"])]
    # Tree A: plaintext branches over d1/d2.  Tree B: ciphertext trunk in d3,
    # which is the single critical domain of tree B (both receivers share it).
    # Each per-branch form change needs its own permit.
    permits = [
        permit("p0a", "P0", "P", "C", "T1", 2, "v2"),
        permit("p0b", "P0", "P", "C", "T1", 2, "v2"),
        permit("p2a", "Y", "C", "P", "T1", 2, "v2"),
        permit("p2b", "Y", "C", "P", "T1", 2, "v2"),
    ]
    return base_doc(
        "case01_shared_domain", "v2", nodes, edges, ["R1", "R2"],
        plain_allowed={"P0", "A", "B", "R1", "R2", "Y"},
        permits=permits, domains=domains,
        check_request={"publish_time": 2, "failed_domain": "d1"},
    )


# --------------------------------------------------------------------------- #
# Case 2: with one domain cut both trees break, yet every receiver keeps one
# intact branch (different receivers survive on different trees).
# --------------------------------------------------------------------------- #

def case_split_survival():
    # Under d3 (or d2) each individual tree loses at least one receiver, but
    # the two trees together keep every receiver on one intact branch.
    nodes = [node("P0", "publisher"), node("A", "relay"), node("B", "relay"),
             node("R1", "receiver"), node("R2", "receiver")]
    edges = [
        # Tree A: P0-A fan-out.
        edge("e01", "P0", "A", "P", domain="d3"),
        edge("e02", "A", "R1", "P", domain="d1"),
        edge("e03", "A", "R2", "P", domain="d2"),
        # Tree B: P0-B fan-out, crossed.
        edge("e04", "P0", "B", "P", domain="d4"),
        edge("e05", "B", "R1", "P", domain="d2"),
        edge("e06", "B", "R2", "P", domain="d1"),
    ]
    domains = [
        # Leaf domains are shared by exactly one edge of each tree, crossed
        # between receivers, so every single fault leaves one branch alive.
        domain("d1", ["e02", "e06"]),
        domain("d2", ["e03", "e05"]),
        domain("d3", ["e01"]),
        domain("d4", ["e04"]),
    ]
    permits: list[dict] = []  # plaintext throughout, no form changes
    return base_doc(
        "case02_split_survival", "v2", nodes, edges, ["R1", "R2"],
        plain_allowed={"P0", "A", "B", "R1", "R2"},
        permits=permits, domains=domains,
        check_request={"publish_time": 1, "failed_domain": "d2"},
    )


# --------------------------------------------------------------------------- #
# Case 3: reusing the cheap edge funnels both trees through one domain and
# destroys fault tolerance; the resilient plan costs more.
# --------------------------------------------------------------------------- #

def case_cheap_reuse():
    nodes = [node("P0", "publisher"), node("A", "relay"), node("B", "relay"),
             node("R1", "receiver"), node("R2", "receiver")]
    edges = [
        # Cheap shared funnel.
        edge("e01", "P0", "A", "PC", domain="d1", cost=1),
        edge("e02", "A", "R1", "PC", domain="d1", cost=1),
        edge("e03", "A", "R2", "PC", domain="d1", cost=1),
        # Pricier disjoint route.
        edge("e04", "P0", "B", "PC", domain="d2", cost=40),
        edge("e05", "B", "R1", "PC", domain="d2", cost=40),
        edge("e06", "B", "R2", "PC", domain="d2", cost=40),
    ]
    domains = [domain("d1", ["e01", "e02", "e03"]),
               domain("d2", ["e04", "e05", "e06"])]
    permits = [
        permit("p1a", "P0", "P", "C", "T1", 2, "v2"),
        permit("p1b", "P0", "P", "C", "T1", 2, "v2"),
        permit("p2a", "A", "C", "P", "T1", 2, "v2"),
        permit("p2b", "A", "C", "P", "T1", 2, "v2"),
        permit("p2c", "A", "C", "P", "T1", 2, "v2"),
        permit("p2d", "A", "C", "P", "T1", 2, "v2"),
    ]
    # The baseline greedily reuses the cheap d1 funnel for both trees.  Each
    # tree holds its own transform permits (one per P branch at A), so all
    # authorizations are valid and the rejection reason is purely the
    # destroyed fault tolerance.
    baseline = {
        "tree_a": tree_spec(
            "baseA", "P0",
            [("e01", "C"), ("e02", "P"), ("e03", "P")],
            [{"node": "P0", "from_label": "P", "to_label": "C", "permit_id": "p1a"},
             {"node": "A", "from_label": "C", "to_label": "P", "permit_id": "p2a"},
             {"node": "A", "from_label": "C", "to_label": "P", "permit_id": "p2b"}]),
        "tree_b": tree_spec(
            "baseB", "P0",
            [("e01", "C"), ("e02", "P"), ("e03", "P")],
            [{"node": "P0", "from_label": "P", "to_label": "C", "permit_id": "p1b"},
             {"node": "A", "from_label": "C", "to_label": "P", "permit_id": "p2c"},
             {"node": "A", "from_label": "C", "to_label": "P", "permit_id": "p2d"}]),
    }
    return base_doc(
        "case03_cheap_reuse", "v2", nodes, edges, ["R1", "R2"],
        plain_allowed={"P0", "A", "B", "R1", "R2"},
        permits=permits, domains=domains, baseline=baseline,
        check_request={"publish_time": 0, "failed_domain": "d1"},
    )


# --------------------------------------------------------------------------- #
# Case 4: a relay is forbidden from seeing plaintext.  The baseline pushes P
# through it and must be rejected at that exact transit point.
# --------------------------------------------------------------------------- #

def case_forbidden_plain():
    nodes = [node("P0", "publisher"), node("A", "relay"), node("B", "relay"),
             node("C", "relay"),
             node("R1", "receiver"), node("R2", "receiver")]
    edges = [
        edge("e01", "P0", "A", "P", domain="d1"),
        edge("e02", "A", "R1", "P", domain="d1"),
        # First disjoint ciphertext route via B.
        edge("e03", "P0", "B", "C", domain="d2"),
        edge("e04", "B", "R2", "C", domain="d2"),
        edge("e05", "B", "R1", "C", domain="d2"),
        # Second disjoint ciphertext route via C-relay (node id CR to avoid
        # clashing with the C encapsulation label conceptually).
        edge("e06", "P0", "C", "C", domain="d3"),
        edge("e07", "C", "R1", "C", domain="d3"),
        edge("e08", "C", "R2", "C", domain="d3"),
    ]
    domains = [domain("d1", ["e01", "e02"]),
               domain("d2", ["e03", "e04", "e05"]),
               domain("d3", ["e06", "e07", "e08"])]
    # A is deliberately absent from plain_allowed; only P0/R1/R2 may see P.
    # The resilient pair uses the two ciphertext routes, while the baseline
    # illegally pushes plaintext through A.  Each tree needs its own P->C permit.
    permits = [
        permit("p1a", "P0", "P", "C", "T1", 2, "v2"),
        permit("p1b", "P0", "P", "C", "T1", 2, "v2"),
        permit("p1c", "P0", "P", "C", "T1", 2, "v2"),
    ]
    baseline = {
        "tree_a": tree_spec(
            "baseA", "P0", [("e01", "P"), ("e02", "P")], []),
        "tree_b": tree_spec(
            "baseB", "P0", [("e03", "C"), ("e04", "C"), ("e05", "C")],
            [{"node": "P0", "from_label": "P", "to_label": "C", "permit_id": "p1a"}]),
    }
    return base_doc(
        "case04_forbidden_plain", "v2", nodes, edges, ["R1", "R2"],
        plain_allowed={"P0", "R1", "R2"},
        permits=permits, domains=domains, baseline=baseline,
        check_request={"publish_time": 2, "failed_domain": None},
    )


# --------------------------------------------------------------------------- #
# Case 5: an old generation arrives after the relay's P permission was
# withdrawn.  The old copy must be dropped before reaching that relay, and the
# new receiver list must not confirm old messages.
# --------------------------------------------------------------------------- #

def case_revoked_generation():
    nodes = [node("P0", "publisher"), node("A", "relay"), node("B", "relay"),
             node("R1", "receiver"), node("R2", "receiver"),
             node("R3", "receiver")]
    edges = [
        edge("e01", "P0", "A", "PC", domain="d1"),
        edge("e02", "A", "R1", "P", domain="d1"),
        edge("e03", "P0", "B", "PC", domain="d2"),
        edge("e04", "B", "R2", "PC", domain="d2"),
        edge("e05", "B", "R3", "C", domain="d2"),
        edge("e06", "A", "R3", "P", domain="d1"),
        # Current-version ciphertext bypass: A lost P permission, so R1 must
        # be reachable without plaintext ever touching A.
        edge("e07", "B", "R1", "C", domain="d2"),
        # Second-route ciphertext spurs through the d1 side (A only forwards
        # ciphertext here, so its withdrawn P permission is irrelevant).
        edge("e08", "A", "R2", "C", domain="d1"),
        edge("e09", "A", "R1", "C", domain="d1"),
        edge("e10", "A", "R3", "C", domain="d1"),
    ]
    domains = [domain("d1", ["e01", "e02", "e06", "e08", "e09", "e10"]),
               domain("d2", ["e03", "e04", "e05", "e07"])]
    permits = [
        permit("p1a", "P0", "P", "C", "T1", 2, "v2"),
        permit("p1b", "P0", "P", "C", "T1", 2, "v2"),
        permit("p2", "B", "C", "P", "T1", 2, "v2"),
    ]
    old_permits = [
        {**permit("op1", "P0", "P", "C", "T1", 1, "v1")},
    ]
    # Both old trees cover the whole old receiver directory {R1, R2}.
    # Old tree A sends plaintext through A; the old directory allowed A.
    # Current plain_allowed excludes A, so the in-flight copy must be cut at
    # the P0->A edge before ever reaching A.
    previous = {
        "version": "v1",
        "tree_a": tree_spec(
            "oldA", "P0", [("e01", "P"), ("e02", "P"),
                           ("e03", "P"), ("e04", "P")], []),
        "tree_b": tree_spec(
            "oldB", "P0",
            [("e03", "C"), ("e04", "C"), ("e07", "C")],
            [{"node": "P0", "from_label": "P", "to_label": "C", "permit_id": "op1"}]),
        "receivers": ["R1", "R2"],
        "plain_allowed": ["A", "B", "P0", "R1", "R2"],
        "permits": old_permits,
        "publish_window": {"earliest": -3, "latest": 2},
        "in_flight": [{"digest": "sha256:synthetic-oldgen", "generation": 1}],
    }
    return base_doc(
        "case05_revoked_generation", "v2", nodes, edges,
        ["R1", "R2", "R3"],
        plain_allowed={"P0", "B", "R1", "R2", "R3"},
        permits=permits, domains=domains, previous=previous,
        check_request={"publish_time": 0, "failed_domain": None},
    )


# --------------------------------------------------------------------------- #
# Case 6: exact-deadline arrival.  delay_max + latest publish == deadline,
# which must be accepted (the deadline is inclusive).
# --------------------------------------------------------------------------- #

def case_exact_deadline():
    nodes = [node("P0", "publisher"), node("A", "relay"), node("B", "relay"),
             node("C", "relay"),
             node("R1", "receiver"), node("R2", "receiver")]
    edges = [
        # Plaintext route in d1; A is P-allowed.
        edge("e01", "P0", "A", "P", domain="d1", dmin=3, dmax=5),
        edge("e02", "A", "R1", "P", domain="d1", dmin=3, dmax=5),
        # Ciphertext route in d2.
        edge("e03", "P0", "B", "C", domain="d2", dmin=3, dmax=5),
        edge("e04", "B", "R2", "C", domain="d2", dmin=3, dmax=5),
        edge("e05", "B", "R1", "C", domain="d2", dmin=3, dmax=5),
        # Independent ciphertext route in d3.
        edge("e06", "P0", "C", "C", domain="d3", dmin=3, dmax=5),
        edge("e07", "C", "R1", "C", domain="d3", dmin=3, dmax=5),
        edge("e08", "C", "R2", "C", domain="d3", dmin=3, dmax=5),
    ]
    domains = [domain("d1", ["e01", "e02"]),
               domain("d2", ["e03", "e04", "e05"]),
               domain("d3", ["e06", "e07", "e08"])]
    # Each ciphertext tree consumes its own publisher P->C authorization.
    permits = [
        permit("p1a", "P0", "P", "C", "T1", 2, "v2"),
        permit("p1b", "P0", "P", "C", "T1", 2, "v2"),
    ]
    # Window latest = 10, two edges * delay_max 5 = 10 -> arrival exactly 20.
    return base_doc(
        "case06_exact_deadline", "v2", nodes, edges, ["R1", "R2"],
        plain_allowed={"P0", "A", "R1", "R2"},
        permits=permits, domains=domains,
        check_request={"publish_time": 10, "failed_domain": None},
        deadline=20, window=(0, 10),
    )


def case_infeasible():
    # Every path to every receiver funnels through one shared edge/domain, so
    # no two trees can survive that domain's failure together.
    nodes = [node("P0", "publisher"), node("A", "relay"),
             node("R1", "receiver"), node("R2", "receiver")]
    edges = [
        edge("e01", "P0", "A", "PC", domain="d1"),
        edge("e02", "A", "R1", "PC", domain="d1"),
        edge("e03", "A", "R2", "PC", domain="d1"),
    ]
    domains = [domain("d1", ["e01", "e02", "e03"])]
    permits = [
        permit("p1a", "P0", "P", "C", "T1", 2, "v2"),
        permit("p1b", "P0", "P", "C", "T1", 2, "v2"),
    ]
    baseline = {
        "tree_a": tree_spec(
            "baseA", "P0", [("e01", "C"), ("e02", "C"), ("e03", "C")],
            [{"node": "P0", "from_label": "P", "to_label": "C", "permit_id": "p1a"}]),
        "tree_b": tree_spec(
            "baseB", "P0", [("e01", "C"), ("e02", "C"), ("e03", "C")],
            [{"node": "P0", "from_label": "P", "to_label": "C", "permit_id": "p1b"}]),
    }
    return base_doc(
        "case08_infeasible", "v2", nodes, edges, ["R1", "R2"],
        plain_allowed={"P0", "A", "R1", "R2"},
        permits=permits, domains=domains, baseline=baseline,
        check_request={"publish_time": 1, "failed_domain": "d1"},
    )


CASES = [
    case_shared_domain,
    case_split_survival,
    case_cheap_reuse,
    case_forbidden_plain,
    case_revoked_generation,
    case_exact_deadline,
    case_infeasible,
]


def main() -> None:
    for builder in CASES:
        write_case(builder.__name__.replace("case_", "") + ".json"
                   if False else builder().get("case_id") + ".json", builder())


if __name__ == "__main__":
    main()
