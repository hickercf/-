from typing import Dict, Any, Optional
from app.core.extractor_agent import extract_by_agent
from app.core.fallback_extractor import extract_by_fallback


def is_valid_chain(result: Optional[Dict[str, Any]]) -> bool:
    if result is None:
        return False
    nodes = result.get("nodes", [])
    if not nodes:
        return False
    return True


def validate_chain(chain: Dict[str, Any]) -> bool:
    required_fields = ["nodes", "edges", "trust_boundary_crossed", "extraction_method", "extraction_confidence"]
    for field in required_fields:
        if field not in chain:
            return False
    for node in chain.get("nodes", []):
        node_fields = ["id", "actor", "tool", "action", "object", "data_type", "permission", "destination", "confidence", "evidence_text"]
        for nf in node_fields:
            if nf not in node:
                return False
    for edge in chain.get("edges", []):
        edge_fields = ["source", "target", "relation", "description"]
        for ef in edge_fields:
            if ef not in edge:
                return False
    return True


def normalize_chain(fallback_result: Dict[str, Any]) -> Dict[str, Any]:
    if is_valid_chain(fallback_result) and validate_chain(fallback_result):
        return fallback_result
    nodes = fallback_result.get("nodes", [])
    edges = fallback_result.get("edges", [])
    if nodes and not validate_chain(fallback_result):
        for i, node in enumerate(nodes):
            node.setdefault("actor", "agent")
            node.setdefault("object", node.get("evidence_text", "")[:50])
            node.setdefault("data_type", "unknown")
            node.setdefault("permission", "unknown")
            node.setdefault("destination", "local")
            node.setdefault("confidence", 0.7)
            node.setdefault("evidence_text", "")
        for i, edge in enumerate(edges):
            edge.setdefault("relation", "then")
            edge.setdefault("description", "")
        fallback_result.setdefault("trust_boundary_crossed", False)
        fallback_result.setdefault("extraction_method", "fallback")
        fallback_result.setdefault("extraction_confidence", 0.7)
    return fallback_result


def merge_and_normalize(agent_result: Dict[str, Any], fallback_result: Dict[str, Any]) -> Dict[str, Any]:
    agent_nodes = agent_result.get("nodes", [])
    fallback_nodes = fallback_result.get("nodes", [])

    seen = set()
    merged_nodes = []
    for n in agent_nodes:
        key = (n.get("action"), n.get("data_type"), n.get("tool"))
        if key not in seen:
            merged_nodes.append(n)
            seen.add(key)

    for n in fallback_nodes:
        key = (n.get("action"), n.get("data_type"), n.get("tool"))
        if key not in seen:
            merged_nodes.append(n)
            seen.add(key)

    merged_edges = list(agent_result.get("edges", []))
    if len(merged_nodes) > 1 and not merged_edges:
        for i in range(len(merged_nodes) - 1):
            merged_edges.append({
                "source": merged_nodes[i].get("id", f"n{i}"),
                "target": merged_nodes[i + 1].get("id", f"n{i + 1}"),
                "relation": "then",
                "description": f"{merged_nodes[i].get('action', '')} 后 {merged_nodes[i + 1].get('action', '')}",
            })

    trust = agent_result.get("trust_boundary_crossed", False) or fallback_result.get("trust_boundary_crossed", False)

    a_conf = agent_result.get("extraction_confidence", 0.8)
    f_conf = fallback_result.get("extraction_confidence", 0.7)
    avg_conf = round((a_conf + f_conf) / 2, 2)

    result = {
        "nodes": merged_nodes,
        "edges": merged_edges,
        "trust_boundary_crossed": trust,
        "extraction_method": "hybrid",
        "extraction_confidence": avg_conf,
    }

    if not validate_chain(result):
        return normalize_chain(result)
    return result


async def extract_behavior_chain(input_type: str, content: str) -> Dict[str, Any]:
    agent_result = await extract_by_agent(input_type, content)
    fallback_result = extract_by_fallback(input_type, content)

    result = None
    if is_valid_chain(agent_result):
        if _is_trivial_fallback(fallback_result):
            result = normalize_chain(agent_result)
        else:
            result = merge_and_normalize(agent_result, fallback_result)
    else:
        result = normalize_chain(fallback_result)

    result["input_type"] = input_type
    result["input_text"] = content
    return result


def _is_trivial_fallback(fallback_result: Dict[str, Any]) -> bool:
    nodes = fallback_result.get("nodes", [])
    if not nodes:
        return True
    for n in nodes:
        action = n.get("action", "unknown")
        tool = n.get("tool", "unknown")
        data_type = n.get("data_type", "unknown")
        if action != "unknown" and tool != "unknown":
            return False
        if data_type not in ("unknown", "public_data"):
            return False
    return True
