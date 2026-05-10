import yaml
import os
from typing import List, Dict, Any, Optional


RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "security_rules.yaml")
RULES_PATH = os.path.normpath(RULES_PATH)


def load_rules() -> List[Dict[str, Any]]:
    if not os.path.exists(RULES_PATH):
        return []
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or []


_rules_cache = None


def get_rules() -> List[Dict[str, Any]]:
    global _rules_cache
    if _rules_cache is None:
        _rules_cache = load_rules()
    return _rules_cache


def reload_rules() -> List[Dict[str, Any]]:
    global _rules_cache
    _rules_cache = load_rules()
    return _rules_cache


def match_node_rule(node: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    if rule.get("type") != "node":
        return False
    cond = rule.get("condition", {})
    if not cond:
        return False
    
    matches = True
    if cond.get("action"):
        if node.get("action") not in cond["action"]:
            matches = False
    if cond.get("data_type"):
        if node.get("data_type") not in cond["data_type"]:
            matches = False
    if cond.get("tool"):
        if node.get("tool") not in cond["tool"]:
            matches = False
    if cond.get("destination"):
        if node.get("destination") not in cond["destination"]:
            matches = False
    if cond.get("permission"):
        if node.get("permission") not in cond["permission"]:
            matches = False
    return matches


def match_chain_rule(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], rule: Dict[str, Any]) -> bool:
    if rule.get("type") != "chain":
        return False
    sequence = rule.get("sequence", [])
    if not sequence or len(sequence) < 2:
        return False
    
    for i in range(len(nodes) - len(sequence) + 1):
        all_match = True
        for j, step in enumerate(sequence):
            node = nodes[i + j]
            if step.get("action") and node.get("action") not in step["action"]:
                all_match = False
                break
            if step.get("data_type") and node.get("data_type") not in step["data_type"]:
                all_match = False
                break
            if step.get("destination") and node.get("destination") not in step["destination"]:
                all_match = False
                break
            if step.get("tool") and node.get("tool") not in step["tool"]:
                all_match = False
                break
        if all_match:
            return True
    return False


def match_rules(behavior_chain: Dict[str, Any]) -> tuple:
    rules = get_rules()
    nodes = behavior_chain.get("nodes", [])
    edges = behavior_chain.get("edges", [])
    matched = []
    total_score = 0
    categories = set()
    
    for rule in rules:
        hit = False
        if rule.get("type") == "node":
            for node in nodes:
                if match_node_rule(node, rule):
                    hit = True
                    break
        elif rule.get("type") == "chain":
            hit = match_chain_rule(nodes, edges, rule)
        
        if hit:
            matched.append({
                "id": rule["id"],
                "name": rule["name"],
                "category": rule.get("category", ""),
                "score": rule.get("score", 0),
                "level": rule.get("level", "medium"),
                "advice": rule.get("advice", ""),
            })
            total_score += rule.get("score", 0)
            if rule.get("category"):
                categories.add(rule["category"])
    
    return matched, total_score, list(categories)
