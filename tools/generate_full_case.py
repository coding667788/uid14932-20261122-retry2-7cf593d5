"""Generate the full-scale synthetic case (18 nodes / 32 edges / 7 receivers).

The topology is hand-authored and frozen into cases/case07_full_scale.json.
It provides two structurally independent multicast trees whose per-receiver
paths never depend on a single shared fault domain.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.generate_cases import (  # noqa: E402
    WINDOW_EARLY, WINDOW_LATE, DEADLINE,
    edge, node, permit, domain, write_case, base_doc,
)


def build() -> dict:
    # 1 publisher, 10 relays, 7 receivers = 18 nodes.
    nodes = (
        [node("P0", "publisher")]
        + [node(f"A{i}", "relay") for i in range(1, 6)]   # A1..A5 tree-a relays
        + [node(f"B{i}", "relay") for i in range(1, 6)]   # B1..B5 tree-b relays
        + [node(f"R{i}", "receiver") for i in range(1, 8)]
    )

    edges: list[dict] = []

    # Tree A side: P0 -> A1/A2 trunks, A3/A4/A5 fan out to receivers.
    # Tree B side: P0 -> B1/B2 trunks, B3/B4/B5 fan out.
    # Six fault domains: d1..d3 partition A-side edges, d4..d6 the B side.
    plan_edges = [
        # A trunk / fan-out (16 edges)
        ("a01", "P0", "A1", "PC", "d1"),
        ("a02", "P0", "A2", "PC", "d2"),
        ("a03", "A1", "A3", "PC", "d1"),
        ("a04", "A1", "A4", "PC", "d2"),
        ("a05", "A2", "A4", "PC", "d3"),
        ("a06", "A2", "A5", "PC", "d3"),
        ("a07", "A3", "R1", "PC", "d1"),
        ("a08", "A3", "R2", "PC", "d1"),
        ("a09", "A4", "R2", "PC", "d2"),
        ("a10", "A4", "R3", "PC", "d2"),
        ("a11", "A4", "R4", "PC", "d2"),
        ("a12", "A5", "R4", "PC", "d3"),
        ("a13", "A5", "R5", "PC", "d3"),
        ("a14", "A3", "R6", "PC", "d1"),
        ("a15", "A5", "R7", "PC", "d3"),
        ("a16", "A1", "R1", "PC", "d1"),
        # B trunk / fan-out (16 edges)
        ("b01", "P0", "B1", "PC", "d4"),
        ("b02", "P0", "B2", "PC", "d5"),
        ("b03", "B1", "B3", "PC", "d4"),
        ("b04", "B1", "B4", "PC", "d5"),
        ("b05", "B2", "B4", "PC", "d6"),
        ("b06", "B2", "B5", "PC", "d6"),
        ("b07", "B3", "R1", "PC", "d4"),
        ("b08", "B3", "R2", "PC", "d4"),
        ("b09", "B4", "R2", "PC", "d5"),
        ("b10", "B4", "R3", "PC", "d5"),
        ("b11", "B4", "R4", "PC", "d5"),
        ("b12", "B5", "R4", "PC", "d6"),
        ("b13", "B5", "R5", "PC", "d6"),
        ("b14", "B3", "R6", "PC", "d4"),
        ("b15", "B5", "R7", "PC", "d6"),
        ("b16", "B1", "R1", "PC", "d6"),
    ]
    assert len(plan_edges) == 32
    for eid, src, dst, labels, did in plan_edges:
        edges.append(edge(eid, src, dst, labels, domain=did,
                          dmin=1, dmax=3, cost=10))

    domains = [
        domain("d1", [e[0] for e in plan_edges if e[4] == "d1"]),
        domain("d2", [e[0] for e in plan_edges if e[4] == "d2"]),
        domain("d3", [e[0] for e in plan_edges if e[4] == "d3"]),
        domain("d4", [e[0] for e in plan_edges if e[4] == "d4"]),
        domain("d5", [e[0] for e in plan_edges if e[4] == "d5"]),
        domain("d6", [e[0] for e in plan_edges if e[4] == "d6"]),
    ]

    receivers = [f"R{i}" for i in range(1, 8)]
    # Every node except none is P-allowed; form changes still need permits.
    plain_allowed = {"P0"} | {n["id"] for n in nodes}

    # Generous permit pool: several independent P->C and C->P authorizations
    # at the trunk roots and fan-out relays.
    permits: list[dict] = []
    seq = 0

    def add(prefix: str, nid: str, frm: str, to: str, count: int) -> None:
        nonlocal seq
        for _ in range(count):
            seq += 1
            permits.append(permit(f"{prefix}{seq:02d}", nid, frm, to,
                                  "T1", 2, "v2"))

    add("pa", "P0", "P", "C", 6)
    for nid in ("A1", "A2", "B1", "B2"):
        add("pc", nid, "C", "P", 3)
    for nid in ("A3", "A4", "A5", "B3", "B4", "B5"):
        add("pf", nid, "C", "P", 2)

    return base_doc(
        "case07_full_scale", "v2", nodes, edges, receivers,
        plain_allowed=plain_allowed, permits=permits, domains=domains,
        topic_cls=3,
        check_request={"publish_time": 2, "failed_domain": "d2"},
        deadline=DEADLINE, window=(WINDOW_EARLY, WINDOW_LATE),
    )


def main() -> None:
    doc = build()
    write_case("case07_full_scale.json", doc)


if __name__ == "__main__":
    main()
