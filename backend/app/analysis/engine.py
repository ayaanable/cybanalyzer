from __future__ import annotations
from collections import Counter
import networkx as nx
from app.schemas.environment import Environment, Node

# Semantic transitions deliberately exclude descriptive-only relationships.
MOVEMENT_EDGES = {"NETWORK_ACCESS", "EXPLOITS", "CAN_LOGIN", "CAN_USE", "CAN_READ", "CAN_WRITE", "CAN_EXECUTE", "CAN_ACCESS", "CAN_ASSUME", "ADMIN_ACCESS", "PRIVILEGE_ESCALATION", "TRUSTS"}
HIGH_PRIVILEGE = {"ADMIN_ACCESS", "PRIVILEGE_ESCALATION", "CAN_ASSUME"}

def _severity(score: float) -> str:
    return "Critical" if score >= 90 else "High" if score >= 75 else "Medium" if score >= 50 else "Low" if score >= 30 else "Informational"

def _build(env: Environment) -> nx.MultiDiGraph:
    """Create movement graph, preserving distinct semantic relationships.

    An edge can declare ``properties.requires_vulnerability``. That transition is
    unavailable when its enabling simulated vulnerability has been removed.
    """
    graph = nx.MultiDiGraph()
    vulnerabilities = {v.id for v in env.vulnerabilities}
    for n in env.nodes: graph.add_node(n.id, node=n)
    for edge in env.relationships:
        requirement = edge.properties.get("requires_vulnerability")
        if edge.type in MOVEMENT_EDGES and (not requirement or requirement in vulnerabilities):
            graph.add_edge(edge.source, edge.target, key=edge.id, relationship=edge)
    return graph

def _node(env: Environment, node_id: str) -> Node: return next(n for n in env.nodes if n.id == node_id)

def _score_path(env: Environment, node_ids: list[str], edge_ids: list[str]) -> tuple[int, list[str], list[str]]:
    relationships = {relationship.id: relationship for relationship in env.relationships}
    edges = [relationships[edge_id] for edge_id in edge_ids]
    vulns = {v.asset_id: v for v in env.vulnerabilities}
    entry = _node(env, node_ids[0])
    exposure = 16 if entry.type == "Internet" or entry.properties.get("publicly_reachable") else 4
    vuln_score = sum(v.severity * 1.25 + v.exploitability * .65 for n, v in vulns.items() if n in node_ids)
    privilege = sum(9 if e.type in HIGH_PRIVILEGE else 3 if e.type in {"CAN_LOGIN", "CAN_EXECUTE"} else 1 for e in edges)
    criticality = _node(env, node_ids[-1]).criticality * 3.2
    permission = sum(7 if e.properties.get("excessive_permission") else 0 for e in edges)
    score = min(100, round(exposure + vuln_score + privilege + criticality + permission))
    techniques = sorted({v.mitre_technique for v in vulns.values() if v.asset_id in node_ids and v.mitre_technique})
    return score, techniques, edge_ids

def _explain(env: Environment, ids: list[str], edge_ids: list[str]) -> str:
    parts = []
    for nid in ids:
        node = _node(env, nid)
        for vuln in env.vulnerabilities:
            if vuln.asset_id == nid:
                parts.append(f"{node.name} has {vuln.name} (severity {vuln.severity}).")
    for a, b, edge_id in zip(ids, ids[1:], edge_ids):
        edge = next(r for r in env.relationships if r.id == edge_id)
        parts.append(f"{_node(env,a).name} {edge.type.replace('_', ' ').lower()} {_node(env,b).name}.")
    return " ".join(parts)

def analyze(env: Environment, entry: str, target: str | None = None, max_depth: int = 7) -> dict:
    graph = _build(env)
    if entry not in graph: raise ValueError("Entry point does not exist")
    targets = [target] if target else [n.id for n in env.nodes if n.criticality >= 8 and n.id != entry]
    paths = []
    for destination in targets:
        if destination not in graph: raise ValueError("Target does not exist")
        try: candidates = nx.all_simple_edge_paths(graph, entry, destination, cutoff=max_depth)
        except nx.NetworkXNoPath: candidates = []
        for edge_path in candidates:
            ids = [entry] + [target_id for _, target_id, _ in edge_path]
            edge_ids = [edge_id for _, _, edge_id in edge_path]
            score, techniques, edge_ids = _score_path(env, ids, edge_ids)
            paths.append({"id": "path-" + "-".join(edge_ids), "node_ids": ids, "relationship_ids": edge_ids, "steps": len(ids)-1, "risk_score": score, "severity": _severity(score), "entry_point": entry, "target": destination, "techniques": techniques, "explanation": _explain(env, ids, edge_ids)})
    paths.sort(key=lambda p: p["risk_score"], reverse=True)
    distribution = Counter(p["severity"] for p in paths)
    return {"paths": paths, "summary": {"attack_paths": len(paths), "critical_paths": distribution["Critical"], "highest_risk": paths[0]["risk_score"] if paths else 0, "risk_distribution": distribution}}

def recommendations(env: Environment, paths: list[dict]) -> list[dict]:
    top = paths[:8]; recs = []
    affected = {n for p in top for n in p["node_ids"]}
    for vuln in env.vulnerabilities:
        if vuln.asset_id in affected and vuln.severity >= 7:
            recs.append({"type":"Patch", "priority":"High", "reference":vuln.asset_id, "text":f"Prioritize patching {vuln.name} on {_node(env, vuln.asset_id).name}."})
    for edge in env.relationships:
        if edge.id in {e for p in top for e in p["relationship_ids"]} and edge.properties.get("excessive_permission"):
            recs.append({"type":"Least privilege", "priority":"High", "reference":edge.id, "text":f"Reduce excessive {edge.type.replace('_',' ').lower()} permission between {_node(env,edge.source).name} and {_node(env,edge.target).name}."})
    return recs
