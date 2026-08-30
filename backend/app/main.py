from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.schemas.environment import Environment, AnalysisRequest, WhatIfRequest
from app.services.store import initialise, list_environments, get_environment, save_environment, delete_environment
from app.analysis.engine import analyze, recommendations

app = FastAPI(title="AttackPathX API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
initialise()

def env_or_404(environment_id: str) -> Environment:
    environment = get_environment(environment_id)
    if not environment: raise HTTPException(404, "Environment not found")
    return environment

@app.get("/api/health")
def health(): return {"status":"ok", "engine":"networkx"}
@app.get("/api/environments")
def environments(): return list_environments()
@app.post("/api/environments", status_code=201)
def create_environment(environment: Environment): return save_environment(environment)
@app.get("/api/environments/{environment_id}")
def environment(environment_id: str): return env_or_404(environment_id)
@app.put("/api/environments/{environment_id}")
def update_environment(environment_id: str, environment: Environment):
    if environment_id != environment.id: raise HTTPException(422, "Path ID and environment ID must match")
    env_or_404(environment_id)
    return save_environment(environment)
@app.delete("/api/environments/{environment_id}", status_code=204)
def remove_environment(environment_id: str):
    if not delete_environment(environment_id): raise HTTPException(404, "Environment not found")
@app.post("/api/environments/{environment_id}/analyze")
def run_analysis(environment_id: str, request: AnalysisRequest):
    try:
        environment = env_or_404(environment_id)
        result = analyze(environment, request.entry_point, request.target, request.max_depth)
        result["recommendations"] = recommendations(environment, result["paths"])
        return result
    except ValueError as exc: raise HTTPException(422, str(exc))
@app.get("/api/environments/{environment_id}/statistics")
def statistics(environment_id: str):
    environment = env_or_404(environment_id)
    result = analyze(environment, "internet") if any(node.id == "internet" for node in environment.nodes) else {"summary":{"attack_paths":0,"critical_paths":0,"highest_risk":0,"risk_distribution":{}}}
    return {"assets":sum(node.kind == "asset" for node in environment.nodes), "identities":sum(node.kind == "identity" for node in environment.nodes), "vulnerabilities":len(environment.vulnerabilities), "critical_vulnerabilities":sum(v.severity >= 9 for v in environment.vulnerabilities), **result["summary"]}
@app.get("/api/environments/{environment_id}/recommendations")
def environment_recommendations(environment_id: str, entry_point: str = "internet"):
    environment = env_or_404(environment_id)
    result = analyze(environment, entry_point)
    return recommendations(environment, result["paths"])
@app.post("/api/environments/{environment_id}/what-if")
def what_if(environment_id: str, request: WhatIfRequest):
    environment = env_or_404(environment_id)
    before = analyze(environment, request.entry_point, request.target, request.max_depth)
    data = environment.model_dump()
    key = {"vulnerability":"vulnerabilities", "relationship":"relationships", "node":"nodes"}[request.remove_type]
    data[key] = [x for x in data[key] if x["id"] != request.remove_id]
    if len(data[key]) == len(getattr(environment, key)):
        raise HTTPException(404, f"{request.remove_type.title()} not found")
    if request.remove_type == "node":
        data["relationships"] = [x for x in data["relationships"] if x["source"] != request.remove_id and x["target"] != request.remove_id]
        data["vulnerabilities"] = [x for x in data["vulnerabilities"] if x["asset_id"] != request.remove_id]
    after = analyze(Environment.model_validate(data), request.entry_point, request.target, request.max_depth)
    return {"before":before["summary"], "after":after["summary"], "paths_eliminated":before["summary"]["attack_paths"]-after["summary"]["attack_paths"], "risk_reduction": round(100*(before["summary"]["highest_risk"]-after["summary"]["highest_risk"])/max(1,before["summary"]["highest_risk"]))}
