from typing import Dict, Any, List


def build_behavior_graph(behavior_chain: Dict[str, Any]) -> Dict[str, Any]:
    nodes = behavior_chain.get("nodes", [])
    edges = behavior_chain.get("edges", [])

    node_map = {n.get("id", f"n{i}"): n for i, n in enumerate(nodes)}

    incoming = {nid: [] for nid in node_map}
    outgoing = {nid: [] for nid in node_map}

    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src in outgoing:
            outgoing[src].append(edge)
        if tgt in incoming:
            incoming[tgt].append(edge)

    trust_crossed = False
    for i, n1 in enumerate(nodes):
        for j, n2 in enumerate(nodes):
            if i != j:
                if _crosses_trust_boundary(n1, n2):
                    trust_crossed = True
                    break
        if trust_crossed:
            break

    if not trust_crossed:
        for n in nodes:
            if n.get("destination") == "external" and n.get("data_type") in (
                "password", "credential", "token", "api_key", "personal_info"
            ):
                trust_crossed = True
                break

    return {
        "trace_id": behavior_chain.get("trace_id", ""),
        "input_type": behavior_chain.get("input_type", "task"),
        "nodes": nodes,
        "edges": edges,
        "node_map": node_map,
        "outgoing": {k: v for k, v in outgoing.items()},
        "incoming": {k: v for k, v in incoming.items()},
        "trust_boundary_crossed": trust_crossed,
        "extraction_method": behavior_chain.get("extraction_method", "fallback"),
        "extraction_confidence": behavior_chain.get("extraction_confidence", 0.7),
    }


def _crosses_trust_boundary(n1: Dict[str, Any], n2: Dict[str, Any]) -> bool:
    sensitive_types = ("password", "credential", "token", "api_key", "personal_info")
    if n1.get("data_type") in sensitive_types and n2.get("destination") == "external":
        return True
    if n1.get("destination") == "local" and n2.get("destination") == "external":
        if n1.get("data_type") in sensitive_types:
            return True
    return False
